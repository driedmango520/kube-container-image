package controllers

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/pkg/errors"

	"github.com/sirupsen/logrus"
)

const (
	DockerSecretPath = "/etc/docker/image-committer/.dockerconfigjson"
)

type RepoAuth struct {
	Username string
	Password string
	Auth     string
}

type DockerSecret struct {
	Auths map[string]RepoAuth
}

var (
	PushImageErrorNoSpace = errors.New("存储空间不足")
)

type ImageSaver interface {
	FilterContainer(ctx context.Context, podName, namespace, containerName string) (string, error)
	SaveImage(ctx context.Context, containerID, newImageTag string) error
	RegistryLogin(ctx context.Context) error
	PushCheck(ctx context.Context, newImageTag string, spaceLeft int64) error
	PushImage(ctx context.Context, imageAddr string) error
}

type DockerImageSaver struct {
	dockerClient *client.Client
	registryAddr string
	registryUser string
	registryPass string
	authStr      string
}

const (
	ContainerEngineDocker = "docker"
)

var ImageSaverProvider = map[string]func(registryAddr, registryUser, registryPass string) ImageSaver{
	ContainerEngineDocker: NewDockerImageSaver,
}

func GetImageSaver(containerEngine, registryAddr, registryUser, registryPass string) ImageSaver {
	if imageSaver, ok := ImageSaverProvider[containerEngine]; ok {
		return imageSaver(registryAddr, registryUser, registryPass)
	}
	// 默认返回docker类型
	return NewDockerImageSaver(registryAddr, registryUser, registryPass)
}

func NewDockerImageSaver(registryAddr, registryUser, registryPass string) ImageSaver {
	dockerOpt := client.FromEnv
	cli, err := client.NewClientWithOpts(dockerOpt, client.WithAPIVersionNegotiation())
	if err != nil {
		logrus.Errorf("New Docker Client NewClientWithOpts failed: %+v", err)
		return nil
	}
	return &DockerImageSaver{
		dockerClient: cli,
		registryAddr: registryAddr,
		registryUser: registryUser,
		registryPass: registryPass,
	}
}

// FilterContainer 获取容器ID
func (s *DockerImageSaver) FilterContainer(ctx context.Context, podName, namespace, containerName string) (string, error) {

	//查询容器列表,TODO使用label过滤
	containers, err := s.dockerClient.ContainerList(ctx, types.ContainerListOptions{Filters: filters.Args{}})
	if err != nil {
		logrus.Errorf("ContainerListError:%+v", err)
		return "", err
	}

	targetContainer := types.Container{}
	for _, oneContainer := range containers {
		for _, name := range oneContainer.Names {
			if strings.Contains(name, podName) &&
				strings.Contains(name, namespace) &&
				!strings.HasPrefix(name, "/k8s_POD_") {
				// 如果未指定容器名称，则默认使用第一个容器
				if containerName == "" {
					targetContainer = oneContainer
					break
				}
				if strings.Contains(name, containerName) {
					targetContainer = oneContainer
					break
				}

			}
		}
	}
	logrus.Infof("过滤出容器：%v", targetContainer.Names)
	if len(targetContainer.Names) == 0 {
		err = fmt.Errorf("未找到目标容器: %s", podName)
		return "", err
	}
	logrus.Infof("过滤到目标容器ID: %s", targetContainer.ID)
	return targetContainer.ID, nil
}

func (s *DockerImageSaver) SaveImage(ctx context.Context, containerID, newImageTag string) error {

	logrus.Infof("镜像制中, 目标容器ID: %s", containerID)
	// 制作镜像
	imageId, err := s.dockerClient.ContainerCommit(ctx, containerID, types.ContainerCommitOptions{
		Pause:  false,
		Config: &container.Config{Image: newImageTag},
	})

	if err != nil {
		logrus.Errorf("镜像制作失败: %+v", err)
		return err
	}
	logrus.Infof("镜像制作成功, imageID: %s", imageId.ID)

	//给镜像打tag
	err = s.dockerClient.ImageTag(ctx, imageId.ID, newImageTag)
	if err != nil {
		logrus.Errorf("镜像tag失败: %+v", err)
		return err
	}
	logrus.Infof("镜像tag成功, newImageTag: %s", newImageTag)
	return nil
}

// RegistryLogin 登录registry
func (s *DockerImageSaver) RegistryLogin(ctx context.Context) error {
	registryHost, err := ParseImageRepo(s.registryAddr)
	if err != nil {
		logrus.Errorf("RepoParseError:%+v", err)
		return err
	}
	//登录registry
	authConfig := registry.AuthConfig{
		Username:      s.registryUser,
		Password:      s.registryPass,
		ServerAddress: registryHost,
	}
	logrus.Info("登录中，请稍后")
	_, err = s.dockerClient.RegistryLogin(ctx, authConfig)
	if err != nil {
		logrus.Errorf("RegistryLoginError:%+v", err)
		return err
	}
	logrus.Info("登录成功。")
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		logrus.Errorf("AuthInfoMarshalError:%+v", err)
		return err
	}
	authStr := base64.URLEncoding.EncodeToString(encodedJSON)
	s.authStr = authStr
	return nil
}

// PushCheck 检查是否还有空间等
func (s *DockerImageSaver) PushCheck(ctx context.Context, newImageTag string, spaceLeft int64) error {
	if spaceLeft == 0 {
		return nil
	}
	existSize, err := s.calculateNewLayerSize(ctx, newImageTag)
	if err != nil {
		logrus.Errorf("calculateNewLayerSizeError:%+v", err)
		return err
	}
	logrus.Infof("存在的镜像层大小: %d", existSize)
	histories, err := s.dockerClient.ImageHistory(ctx, newImageTag)
	if err != nil {
		logrus.Errorf("ImageHistoryError:%+v", err)
	}
	newImageSize := int64(0)
	for _, val := range histories {
		newImageSize += val.Size
		logrus.Infof("LayerID: %v, CreateTime: %v,Size: %v", val.ID, val.Created, val.Size)
	}
	logrus.Infof("新镜像大小: %d", newImageSize)
	if newImageSize-existSize > spaceLeft {
		return errors.Wrap(PushImageErrorNoSpace, fmt.Sprintf("存储空间不足, 剩余空间: %d", spaceLeft))
	}
	return nil
}

// PushImage 推送镜像
func (s *DockerImageSaver) PushImage(ctx context.Context, imageAddr string) error {
	registryHost, err := ParseImageRepo(s.registryAddr)
	if err != nil {
		logrus.Errorf("RepoParseError:%+v", err)
		return err
	}
	//登录registry
	authConfig := registry.AuthConfig{
		Username:      s.registryUser,
		Password:      s.registryPass,
		ServerAddress: registryHost,
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		logrus.Errorf("AuthInfoMarshalError:%+v", err)
		return err

	}
	authStr := base64.URLEncoding.EncodeToString(encodedJSON)
	logrus.Infof("镜像推送中，请耐心等待")
	// 推送镜像
	pushResp, err := s.dockerClient.ImagePush(ctx, imageAddr, types.ImagePushOptions{
		All:          false,
		RegistryAuth: authStr,
	})

	defer pushResp.Close()
	resultWriter := PushResultWrite{}
	_, err = io.Copy(resultWriter, pushResp)
	if err != nil {
		logrus.Errorf("PushImageError:%+v", err)
		return err
	}
	return nil
}

// 计算需要新增上传的镜像层大小
func (s *DockerImageSaver) calculateNewLayerSize(ctx context.Context, imageAddr string) (int64, error) {
	// 获取镜像信息
	imageInspect, _, err := s.dockerClient.ImageInspectWithRaw(ctx, imageAddr)
	if err != nil {
		logrus.Errorf("ImageInspectError:%+v", err)
		return 0, err
	}

	totalSize := int64(0)
	repo, err := NewRepoMetadata(imageAddr, s.registryUser, s.registryPass)
	if err != nil {
		logrus.Errorf("NewRepoMetadataError:%+v", err)
		return 0, err
	}
	logrus.Infof("开始计算镜像层信息: %v", imageInspect)
	// 遍历镜像的所有层
	for _, layer := range imageInspect.RootFS.Layers {
		layerHash := layer
		// 检查层是否已经存在于仓库
		layerExist, layerSize, err := repo.LayerExistsInRepo(layerHash)
		if err != nil {
			logrus.Errorf("LayerExistsInRepoError:%+v", err)
			return 0, err
		}
		if layerExist {
			// 获取层的大小
			totalSize += layerSize
		}
	}

	return totalSize, nil
}

func ReadImageSecret(registryAddr string, secretPath string) (loginUserName string, loginPassword string, err error) {
	content, err := ioutil.ReadFile(secretPath) //读取整个文件
	//content, err := ioutil.ReadFile(DockerSecretPath) //读取整个文件
	if err != nil {
		logrus.Errorf("ReadFileError:%+v", err)
		return
	}

	dockerSecret := &DockerSecret{}
	err = json.Unmarshal(content, dockerSecret)
	if err != nil {
		logrus.Errorf("UnmarshalError:%+v", err)
		return
	}

	for key, val := range dockerSecret.Auths {
		if key != registryAddr {
			continue
		}
		loginUserName = val.Username
		loginPassword = val.Password
	}
	return loginUserName, loginPassword, nil
}

func Execute(podName, namespace, imageAddr, containerName string) (err error) {
	if !isFileExist(DockerSecretPath) {
		logrus.Errorf("getClientError:%+v", "获取秘钥信息失败：文件不存在")
		err = fmt.Errorf("获取秘钥信息失败：文件不存在")
		return
	}

	if podName == "" || namespace == "" || imageAddr == "" {
		err = fmt.Errorf("pod名称或者命名空间为空, podName:%s, namespace: %s, imageName: %s", podName, namespace, imageAddr)
		logrus.Errorf("关键参数错误: %+v", err)
		return err
	}

	var loginUserName string
	var loginPassword string
	//todo 解析 imageAddr 出 registryAddr

	loginUserName, loginPassword, err = ReadImageSecret(imageAddr, DockerSecretPath)
	if err != nil {
		logrus.Errorf("ReadImageSecretError:%+v", err)
		return
	}

	// 使用 DockerImageSaver优化下列逻辑
	dockerImageSaver := NewDockerImageSaver(imageAddr, loginUserName, loginPassword)

	ctx := context.Background()
	imageID, err := dockerImageSaver.FilterContainer(ctx, podName, namespace, containerName)
	if err != nil {
		logrus.Errorf("FilterContainerError:%+v", err)
		return err
	}

	// 制作镜像
	err = dockerImageSaver.SaveImage(ctx, imageID, imageAddr)
	if err != nil {
		logrus.Errorf("SaveImageError:%+v", err)
		return err
	}

	err = dockerImageSaver.RegistryLogin(ctx)
	if err != nil {
		logrus.Errorf("RegistryLoginError:%+v", err)
		return err
	}
	err = dockerImageSaver.PushCheck(ctx, imageAddr, 0)
	if err != nil {
		logrus.Errorf("PushCheckError:%+v", err)
		return err
	}

	begin := time.Now()
	logrus.Infof("当前时间: %s, 镜像: %s 推送中......", begin.Format(time.RFC3339Nano), imageAddr)
	err = dockerImageSaver.PushImage(ctx, imageAddr)
	if err != nil {
		logrus.Errorf("PushImageError:%+v", err)
		return err
	}
	end := time.Now()
	logrus.Infof("当前时间: %s, 用时: %fs,镜像推送结束", end.Format(time.RFC3339Nano), end.Sub(begin).Seconds())
	return nil
}

type RepoMetadata struct {
	Scheme    string   `json:"scheme"`
	RepoHost  string   `json:"repo_host"`
	Project   string   `json:"project"`
	ImageName string   `json:"image_name"`
	Tag       string   `json:"tag"`
	Auth      RepoAuth `json:"auth"`
}

// NewRepoMetadata 解析镜像地址生成 RepoMetadata 结构体
func NewRepoMetadata(imageAddr string, username, passwd string) (*RepoMetadata, error) {
	// 如果没有协议，需要补上协议，默认为https
	if !strings.HasPrefix(imageAddr, "http") {
		imageAddr = "https://" + imageAddr
	}
	parsedUrl, err := url.Parse(imageAddr)
	if err != nil {
		logrus.Errorf("ParseUrlError:%+v", err)
		return nil, err
	}

	scheme := parsedUrl.Scheme
	if scheme == "" {
		scheme = "https"
	}

	repoHost := parsedUrl.Host
	path := parsedUrl.Path
	if path == "" {
		path = strings.SplitN(imageAddr, "/", 2)[1]
	}

	parts := strings.Split(path, "/")
	var project, imageNameWithTag string
	if len(parts) > 1 {
		project = strings.Join(parts[:len(parts)-1], "/")
		imageNameWithTag = parts[len(parts)-1]
	} else {
		imageNameWithTag = parts[0]
	}

	imageNameAndTag := strings.SplitN(imageNameWithTag, ":", 2)
	imageName := imageNameAndTag[0]
	tag := "latest"
	if len(imageNameAndTag) > 1 {
		tag = imageNameAndTag[1]
	}

	return &RepoMetadata{
		Scheme:    scheme,
		RepoHost:  repoHost,
		Project:   project,
		ImageName: imageName,
		Tag:       tag,
		Auth: RepoAuth{
			Username: username,
			Password: passwd,
		},
	}, nil
}

// LayerExistsInRepo 检查镜像层是否存在于 Harbor 仓库
func (r *RepoMetadata) LayerExistsInRepo(layerHash string) (bool, int64, error) {
	// 构建请求 URL，需要加上sha256: ，不然会一直报401
	blobUrl := fmt.Sprintf("%s://%s/v2/%s/%s/blobs/%s", r.Scheme, r.RepoHost, r.Project, r.ImageName, layerHash)

	// 创建 HTTP 请求
	req, err := http.NewRequest("HEAD", blobUrl, nil)
	if err != nil {
		logrus.Errorf("NewRequestError:LayerExistsInRepo: %+v", err)
		return false, 0, err
	}

	// 设置基本认证
	req.SetBasicAuth(r.Auth.Username, r.Auth.Password)

	// 创建一个不进行证书验证的 HTTP 传输对象
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: tr,
	}
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("DoRequestError:LayerExistsInRepo: %+v", err)
		return false, 0, err
	}
	defer resp.Body.Close()
	exist := resp.StatusCode == http.StatusOK
	if !exist {
		return false, 0, nil
	}
	// 从头部content_length 获取 层大小
	layerSize, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil {
		logrus.Errorf("ParseIntError:%+v", err)
		return false, 0, err
	}

	// 根据响应状态码判断层是否存在
	return resp.StatusCode == http.StatusOK, layerSize, nil
}

func isFileExist(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) { //文件不存在
			return false
		}
	} else {
		return true
	}
	return false
}

type PushResult struct {
	Id             string      `json:"id"`
	Status         string      `json:"status"`
	ProgressDetail interface{} `json:"progressDetail"`
	ErrorDetail    interface{} `json:"errorDetail"`
	Error          string      `json:"error"`
}

type PushResultWrite struct {
}

func (prw PushResultWrite) Write(p []byte) (n int, err error) {
	n = len(p)
	resultStr := string(p)
	fmt.Println(resultStr)
	results := strings.Split(resultStr, "\r\n")
	for _, result := range results {
		if result == "" {
			return n, nil
		}
		curTime := time.Now()
		pushResult := &jsonmessage.JSONMessage{}
		err = json.Unmarshal([]byte(result), pushResult)
		if err != nil {
			logrus.Errorf("当前时间: %s, 镜像推送Unmarshal日志失败，原因： %+v", curTime.Format(time.RFC3339), pushResult.Error.Error())
			return 0, err
		}
		if pushResult.Error != nil && pushResult.Error.Message != "" {
			if strings.Contains(pushResult.Error.Message, "will exceed the configured upper limit") {
				logrus.Infof("当前时间: %s, 镜像推送失败，原因： %+v", curTime.Format(time.RFC3339), pushResult.Error.Error())
				return 0, PushImageErrorNoSpace
			}
			return 0, fmt.Errorf("当前时间: %s, 镜像保存报错: %v", curTime.Format(time.RFC3339), pushResult.Error)
		}
		progress := 0
		if pushResult.Progress != nil {
			progress = int(pushResult.Progress.Current)
		}
		// TODO 每次有新进展时，打印日志
		logrus.Infof("当前时间: %s, 镜像推送中，id: %v,状态：%v ,进度详情： %+v, 总进度：%v", curTime.Format(time.RFC3339), pushResult.ID, pushResult.Status, progress, pushResult.Progress.Total)
	}

	return n, nil
}
