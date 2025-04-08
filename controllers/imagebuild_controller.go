/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	kubeclientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/source"

	imagev1 "github.com/driedmango520/kube-container-image/api/image.driedmango.io/v1"
)

type ImagePushRequest struct {
	buildImage *imagev1.ImageBuild
	Username   string
	Password   string
}

// ImageBuildReconciler reconciles a ImageBuild object
type ImageBuildReconciler struct {
	client.Client
	NodeName  string
	Scheme    *runtime.Scheme
	Log       logr.Logger
	apiReader client.Reader
	// Recorder is an event recorder for recording Event resources to the Kubernetes API.
	Recorder record.EventRecorder
	// KubeClientSet is a standard kubernetes clientset.
	KubeClientSet kubeclientset.Interface
	pushChan      chan ImagePushRequest
	pushingMap    map[types.UID]bool
}

//+kubebuilder:rbac:groups=image.driedmango.io,resources=imagebuilds,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=image.driedmango.io,resources=imagebuilds/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=image.driedmango.io,resources=imagebuilds/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *ImageBuildReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	logger := log.FromContext(ctx).WithValues("imagebuild", req.NamespacedName)
	imageBuild := &imagev1.ImageBuild{}
	if err := r.Get(ctx, req.NamespacedName, imageBuild); err != nil {
		logger.Info("Resource not found", "error", err)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Record last reconcile time
	now := metav1.Now()
	imageBuild.Status.LastReconcileTime = &now

	// Handle deletion logic
	if !imageBuild.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	// Initialize status
	if imageBuild.Status.StartTime == nil {
		imageBuild.Status.StartTime = &now
	}

	// Get target Pod
	pod, err := r.getTargetPod(ctx, imageBuild)
	if err != nil {
		return ctrl.Result{}, r.handlePodError(ctx, imageBuild, err, logger)
	}

	// Check node assignment
	if pod.Spec.NodeName != r.NodeName {
		logger.Info("Pod not scheduled on this node", "node", r.NodeName)
		return ctrl.Result{}, nil
	}

	// Check Pod status, if not running but in terminal state, update ImageBuild status to failed
	if pod.Status.Phase == corev1.PodFailed || pod.Status.Phase == corev1.PodSucceeded {
		return ctrl.Result{}, r.updateStatus(ctx, imageBuild, imagev1.ImageBuildFailed, "PodInTerminalState",
			fmt.Sprintf("Pod is in terminal state %s", pod.Status.Phase), logger)
	}

	// State machine flow, after updating status, will trigger re-entry
	switch imageBuild.Status.Phase {
	case "":
		fallthrough
	case imagev1.ImageBuildCreated:
		return r.handleInitialPhase(ctx, imageBuild, pod, logger)
	case imagev1.ImageBuildCommitted:
		return r.handleCommittedPhase(ctx, imageBuild, logger)
	case imagev1.ImageBuildPushing:
		return r.handlePushingPhase(ctx, imageBuild, logger)
	case imagev1.ImageBuildSucceeded, imagev1.ImageBuildFailed:
		return ctrl.Result{}, nil
	default:
		return ctrl.Result{}, r.updateStatus(ctx, imageBuild, imagev1.ImageBuildFailed, "InvalidPhase",
			fmt.Sprintf("Unknown phase %s", imageBuild.Status.Phase), logger)
	}
}

func (r *ImageBuildReconciler) handleInitialPhase(ctx context.Context, imageBuild *imagev1.ImageBuild, pod *corev1.Pod, logger logr.Logger) (ctrl.Result, error) {
	// Create status
	err := r.updateStatus(ctx, imageBuild, imagev1.ImageBuildCreated, "Created", "Image build request created", logger)
	if err != nil {
		logger.Error(err, "Failed to update ImageBuild", "Phase", imagev1.ImageBuildFailed)
		return ctrl.Result{}, err
	}

	// Add finalizer
	if err = r.addFinalizerToPod(ctx, pod); err != nil {
		return ctrl.Result{}, r.updateStatus(ctx, imageBuild, imagev1.ImageBuildFailed, "FinalizerAddFailed", err.Error(), logger)
	}
	logrus.Infof("ImageBuild addFinalizerToPod, pod %s/%s", pod.Namespace, pod.Name)

	// Check Pod status
	if pod.Status.Phase != corev1.PodRunning {
		return ctrl.Result{}, r.updateStatus(ctx, imageBuild, imagev1.ImageBuildFailed, "PodNotRunning",
			fmt.Sprintf("Pod is in phase %s", pod.Status.Phase), logger)
	}

	// Execute save logic
	imageAuth, err := r.getRegistrySecret(ctx, imageBuild)
	if err != nil {
		logrus.Error(err, "handleInitialPhase Failed to get registry secret")
		return r.handleExecutionError(ctx, pod, imageBuild, err, false, logger)
	}
	logrus.Infof("ImageBuild getRegistrySecret success")

	// Use DockerImageSaver to optimize the following logic
	dockerImageSaver := NewDockerImageSaver(imageBuild.Spec.ImageAddr, imageAuth.Username, imageAuth.Password)

	imageID, err := dockerImageSaver.FilterContainer(ctx, imageBuild.Spec.PodName, imageBuild.Spec.NameSpace, imageBuild.Spec.ContainerName)
	if err != nil {
		logrus.Errorf("FilterContainerError: %+v", err)
		return r.handleExecutionError(ctx, pod, imageBuild, err, false, logger)
	}

	// Build image
	err = dockerImageSaver.SaveImage(ctx, imageID, imageBuild.Spec.ImageAddr)
	if err != nil {
		logrus.Errorf("SaveImageError:%+v", err)
		return r.handleExecutionError(ctx, pod, imageBuild, err, false, logger)
	}

	// Enter commit phase
	return ctrl.Result{}, r.updateStatus(ctx, imageBuild, imagev1.ImageBuildCommitted, "Committed", "Image save completed", logger)
}

func (r *ImageBuildReconciler) handleCommittedPhase(ctx context.Context, imageBuild *imagev1.ImageBuild, logger logr.Logger) (result ctrl.Result, err error) {
	// Execute login and push check
	imageAuth, err := r.getRegistrySecret(ctx, imageBuild)
	if err != nil {
		logrus.Error(err, "Failed to get registry secret")
		return r.handleExecutionError(ctx, nil, imageBuild, err, false, logger)
	}

	// Use DockerImageSaver to optimize the following logic
	dockerImageSaver := NewDockerImageSaver(imageBuild.Spec.ImageAddr, imageAuth.Username, imageAuth.Password)
	err = dockerImageSaver.PushCheck(ctx, imageBuild.Spec.ImageAddr, imageBuild.Spec.SpaceLeft)
	if err != nil {
		logrus.Errorf("PushCheckError: %+v", err)
		return r.handleExecutionError(ctx, nil, imageBuild, err, false, logger)
	}
	// Enter push phase
	return result, r.updateStatus(ctx, imageBuild, imagev1.ImageBuildPushing, "Pushing", "Starting image push", logger)
}

func (r *ImageBuildReconciler) handlePushingPhase(ctx context.Context, imageBuild *imagev1.ImageBuild, logger logr.Logger) (ctrl.Result, error) {
	// Execute push logic
	imageAuth, err := r.getRegistrySecret(ctx, imageBuild)
	if err != nil {
		logger.Error(err, "Failed to get registry secret")
		return r.handleExecutionError(ctx, nil, imageBuild, err, false, logger)
	}
	pushReq := ImagePushRequest{
		buildImage: imageBuild,
		Username:   imageAuth.Username,
		Password:   imageAuth.Password,
	}
	r.pushChan <- pushReq
	return ctrl.Result{}, nil
}

func (r *ImageBuildReconciler) backgroundPushing(ctx context.Context) {
	for pushRequest := range r.pushChan {
		reqCopy := pushRequest
		// 检查是否有推送中
		if r.pushingMap[reqCopy.buildImage.UID] {
			logrus.Infof("name %s PushingMap has already been set, skip this request", reqCopy.buildImage.Name)
			continue
		}
		go func(req ImagePushRequest) {
			r.pushingMap[req.buildImage.UID] = true
			// 退出时删除推送中记录
			defer delete(r.pushingMap, req.buildImage.UID)
			logger := log.FromContext(ctx).WithValues("imagebuild", req.buildImage.Namespace)
			// Use DockerImageSaver to optimize the following logic
			dockerImageSaver := NewDockerImageSaver(req.buildImage.Spec.ImageAddr, req.Username, req.Password)
			//TODO 推送日志优化
			err := dockerImageSaver.PushImage(ctx, req.buildImage.Spec.ImageAddr)
			if err != nil {
				logrus.Errorf("PushImageError:%+v", err)
				// 失败会更新重试次数，再次入队
				_, err = r.handleExecutionError(ctx, nil, req.buildImage, err, true, logger)
				if err != nil {
					logrus.Errorf("UpdateStatusError:%+v", err)
					return
				}
			}

			// Complete process
			err = r.updateStatus(ctx, req.buildImage, imagev1.ImageBuildSucceeded, "Succeeded", "Image push succeeded", logger)
			if err != nil {
				logrus.Errorf("UpdateStatusError:%+v", err)
				return
			}
		}(reqCopy)
	}

}

// getRegistrySecret gets the image registry secret
func (r *ImageBuildReconciler) getRegistrySecret(ctx context.Context, imageBuild *imagev1.ImageBuild) (*RepoAuth, error) {
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Namespace: imageBuild.Namespace,
		Name:      imageBuild.Spec.SecretName,
	}, secret)
	if err != nil {
		logrus.Errorf("GetSecretError:%+v", err)
		return nil, err
	}
	logrus.Infof("GetSecret success")
	dataKey := ".dockerconfigjson"
	dockerSecret := &DockerSecret{}
	err = json.Unmarshal(secret.Data[dataKey], dockerSecret)
	if err != nil {
		logrus.Errorf("UnmarshalError:%+v", err)
		return nil, err
	}
	// Parse image address to get registry host
	registryHost, err := ParseImageRepo(imageBuild.Spec.ImageAddr)
	if err != nil {
		logrus.Errorf("ParseImageRepoError:%+v", err)
		return nil, err
	}

	for key, val := range dockerSecret.Auths {
		if key != registryHost {
			continue
		}
		return &val, nil
	}
	return nil, fmt.Errorf("RepoAuth not found in secret")
}

func (r *ImageBuildReconciler) GetControllerName() string {
	return fmt.Sprintf("%s-imagebuild-controller", r.NodeName)
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageBuildReconciler) SetupWithManager(mgr ctrl.Manager, nodeName string) error {
	r.NodeName = nodeName
	kubeConfig := ctrl.GetConfigOrDie()
	r.KubeClientSet = kubeclientset.NewForConfigOrDie(kubeConfig)
	r.Log = log.Log
	r.Recorder = mgr.GetEventRecorderFor(r.GetControllerName())
	r.apiReader = mgr.GetAPIReader()
	r.pushChan = make(chan ImagePushRequest, 200)
	r.pushingMap = make(map[types.UID]bool)

	c, err := controller.New(r.GetControllerName(), mgr, controller.Options{
		Reconciler: r,
	})
	if err != nil {
		logrus.Errorf("NewControllerError:%+v", err)
		return err
	}

	if err = c.Watch(&source.Kind{Type: &imagev1.ImageBuild{}}, &handler.EnqueueRequestForObject{},
		predicate.Funcs{
			CreateFunc: r.onOwnerCreateFunc(),
		},
	); err != nil {
		logrus.Errorf("WatchError:%+v", err)
		return err
	}
	// 启动后台推送协程
	go r.backgroundPushing(context.Background())

	return ctrl.NewControllerManagedBy(mgr).
		For(&imagev1.ImageBuild{}).
		Complete(r)
}

// onOwnerCreateFunc modify creation condition.
func (r *ImageBuildReconciler) onOwnerCreateFunc() func(event.CreateEvent) bool {
	return func(e event.CreateEvent) bool {
		imageBuild, ok := e.Object.(*imagev1.ImageBuild)
		if !ok {
			return true
		}
		logger := log.FromContext(context.Background()).WithValues("imagebuild", types.NamespacedName{
			Namespace: imageBuild.Namespace,
			Name:      imageBuild.Spec.SecretName,
		})
		err := r.updateStatus(context.Background(), imageBuild, imagev1.ImageBuildCreated, "Created", "ImageBuildCreated", logger)
		if err != nil {
			logger.Error(err, "Failed to update ImageBuild", "Phase", imagev1.ImageBuildFailed)
			return false
		}
		return true
	}
}

// getPod gets the Pod object
func (r *ImageBuildReconciler) getTargetPod(ctx context.Context, imageBuildter *imagev1.ImageBuild) (*corev1.Pod, error) {
	pod := &corev1.Pod{}
	err := r.Get(ctx, types.NamespacedName{
		Namespace: imageBuildter.Namespace,
		Name:      imageBuildter.Spec.PodName,
	}, pod)
	return pod, err
}

// handlePodError handles errors when getting Pod
func (r *ImageBuildReconciler) handlePodError(ctx context.Context, imageBuild *imagev1.ImageBuild, err error, logger logr.Logger) error {
	logger.Info("Failed to get target pod", "error", err)
	return r.updateStatus(ctx, imageBuild, imagev1.ImageBuildFailed, "PodGetFailed", err.Error(), logger)
}

func (r *ImageBuildReconciler) handleExecutionError(ctx context.Context, pod *corev1.Pod, imageBuild *imagev1.ImageBuild, err error, shouldRetry bool, logger logr.Logger) (ctrl.Result, error) {
	// Increase retry count in status
	imageBuild.Status.RetryTimes++
	logger.Info("Execution failed", "retry", imageBuild.Status.RetryTimes, "maxRetry", imageBuild.Spec.MaxRetry)
	if !shouldRetry {
		err = r.updateStatus(ctx, imageBuild, imagev1.ImageBuildFailed, "BuildFailed", err.Error(), logger)
		if err != nil {
			logger.Error(err, "Failed to update ImageBuild status to Failed")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if imageBuild.Status.RetryTimes >= imageBuild.Spec.MaxRetry {
		// If multiple save failures occur, need to release pod finalizer
		if err := r.removeFinalizerFromPod(ctx, pod); err != nil {
			logger.Error(err, "Failed to remove finalizer from ImageBuild")
			return ctrl.Result{}, err
		}
	}
	// Update retry count, currently only image push failures need retry
	err = r.updateStatus(ctx, imageBuild, imagev1.ImageBuildPushing, "PushFailed", err.Error(), logger)
	if err != nil {
		logger.Error(err, "Failed to update ImageBuild status to Failed")
		return ctrl.Result{}, err
	}
	// Requeue
	return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
}

// addFinalizerToPod adds finalizer to Pod
func (r *ImageBuildReconciler) addFinalizerToPod(ctx context.Context, pod *corev1.Pod) error {
	if !containsString(pod.Finalizers, imagev1.ImageBuildFinalizer) {
		pod.Finalizers = append(pod.Finalizers, imagev1.ImageBuildFinalizer)
		return r.Update(ctx, pod)
	}
	return nil
}

// removeFinalizerFromPod removes finalizer from Pod
func (r *ImageBuildReconciler) removeFinalizerFromPod(ctx context.Context, pod *corev1.Pod) error {
	if pod == nil {
		return nil
	}
	pod.Finalizers = removeString(pod.Finalizers, imagev1.ImageBuildFinalizer)
	return r.Update(ctx, pod)
}

// updateStatus 统一状态更新方法
func (r *ImageBuildReconciler) updateStatus(ctx context.Context, original *imagev1.ImageBuild,
	phase imagev1.ImageConditionType, reason, message string, logger logr.Logger) error {

	now := metav1.Now()
	condition := imagev1.ImageBuildCondition{
		Type:               phase,
		Status:             corev1.ConditionTrue,
		Reason:             reason,
		Message:            message,
		LastUpdateTime:     now,
		LastTransitionTime: now,
	}
	imageBuild := original.DeepCopy() // 保存原始副本

	// 更新现有条件状态
	found := false
	for i := range imageBuild.Status.Conditions {
		if imageBuild.Status.Conditions[i].Type == phase {
			imageBuild.Status.Conditions[i] = condition
			found = true
			break
		}
	}
	if !found {
		imageBuild.Status.Conditions = append(imageBuild.Status.Conditions, condition)
	}
	imageBuild.Status.LastReconcileTime = &now

	imageBuild.Status.Phase = phase
	if isTerminalPhase(phase) {
		imageBuild.Status.CompletionTime = &now
	}
	merged := client.MergeFrom(original.DeepCopy())
	// 使用 Patch 避免并发冲突
	err := r.Status().Patch(ctx, imageBuild, merged)
	if err != nil {
		logger.Error(err, "failed to update ImageBuild status")
		return err
	}

	//imageBuild = imageBuild.DeepCopy()
	//imageBuild.Status = *imageBuild.Status.DeepCopy()
	//imageBuild.Status.LastReconcileTime = &metav1.Time{Time: time.Now()}
	//
	//// 使用 Patch 避免并发冲突
	//err := r.Status().Update(ctx, imageBuild)
	//if err != nil {
	//	logger.Error(err, "failed to update ImageBuild status")
	//	return err
	//}
	return nil
}

// 辅助函数集合
func isTerminalPhase(phase imagev1.ImageConditionType) bool {
	return phase == imagev1.ImageBuildSucceeded || phase == imagev1.ImageBuildFailed
}
