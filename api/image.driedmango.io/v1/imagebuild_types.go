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

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

const ImageBuildKind = "ImageBuild"
const ImageBuildFinalizer = "driedmango.io/image-build-finalizer"

// +k8s:openapi-gen=true
// +k8s:deepcopy-gen=true
// ImageConditionType defines all kinds of types of JobStatus.
type ImageConditionType string

const (
	// ImageBuildCreated means the job has been accepted by the system
	ImageBuildCreated ImageConditionType = "Created"

	//ImageBuildCommitted means image have been saved
	ImageBuildCommitted ImageConditionType = "Committed"

	//ImageBuildPushing means image being pushed
	ImageBuildPushing ImageConditionType = "Pushing"

	// ImageBuildSucceeded means image push success
	ImageBuildSucceeded ImageConditionType = "Succeeded"

	// ImageBuildFailed means image save failed， reached phase failed with no restarting
	ImageBuildFailed ImageConditionType = "Failed"
)

// +k8s:openapi-gen=true
// +k8s:deepcopy-gen=true
// ImageBuildSpec defines the desired state of ImageBuild
type ImageBuildSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	PodName string `json:"podName,omitempty"`
	// pod所在的命名空间
	NameSpace string `json:"namespace,omitempty"`
	//pod里面的容器名
	ContainerName string `json:"containerName,omitempty"`
	//要保存的镜像完整地址信息
	ImageAddr string `json:"ImageAddr,omitempty"`
	// 镜像保存的仓库信息，存储在secret中
	SecretName string `json:"secretName,omitempty"`
	// 推送失败时最大重试次数
	MaxRetry int32 `json:"maxRetry,omitempty"`
	// 镜像仓库剩余配额，单位为字节
	SpaceLeft int64 `json:"spaceLeft,omitempty"`
}

// +k8s:openapi-gen=true
// +k8s:deepcopy-gen=true
// ImageBuildCondition describes the state of the job at a certain point.
type ImageBuildCondition struct {
	Type ImageConditionType `json:"type"`
	// Status of the condition, one of True, False, Unknown.
	Status corev1.ConditionStatus `json:"status"`
	// The reason for the condition's last transition.
	Reason string `json:"reason,omitempty"`
	// A human readable message indicating details about the transition.
	Message string `json:"message,omitempty"`
	// The last time this condition was updated.
	LastUpdateTime metav1.Time `json:"lastUpdateTime,omitempty"`
	// Last time the condition transitioned from one status to another.
	LastTransitionTime metav1.Time `json:"lastTransitionTime,omitempty"`
}

// +k8s:openapi-gen=true
// +k8s:deepcopy-gen=true
// ImageBuildStatus defines the observed state of ImageBuild
type ImageBuildStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Phase      ImageConditionType    `json:"phase,omitempty"`
	Conditions []ImageBuildCondition `json:"conditions"`
	// 任务启动时间
	StartTime *metav1.Time `json:"startTime,omitempty"`
	// 任务结束时间
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
	// 上次调度时间
	LastReconcileTime *metav1.Time `json:"lastReconcileTime,omitempty"`
	// 失败原因
	Reason string `json:"reason,omitempty" protobuf:"bytes,4,opt,name=reason"`
	//已经重试次数
	RetryTimes int32 `json:"retryTimes,omitempty" `
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +resource:path=imagebuild
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="State",type=string,JSONPath=`.status.conditions[-1:].type`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ImageBuild is the Schema for the imagebuilds API
type ImageBuild struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ImageBuildSpec   `json:"spec,omitempty"`
	Status ImageBuildStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// ImageBuildList contains a list of ImageBuild
type ImageBuildList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImageBuild `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ImageBuild{}, &ImageBuildList{})
}
