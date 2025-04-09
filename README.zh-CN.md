# kube-image-builder
pod镜像构建工具
工作原理如下：
- 以daemonset方式部署Pod，监听CR资源，具备获取secret的权限
- 监听CR资源，判断对应pod是否在本机节点上，是的话修改CR资源状态，开始处理
- 保存镜像前，先给对应Pod添加finalizer
- 将docker.socket挂载到daemonset pod内，从而可以在pod连接docker
- 读取CR里面的镜像仓库secret信息，并解析出来
- 调用ImageSaver构建镜像，并推送到镜像仓库
- 删除pod finalizer
- 修改CR状态为成功

当前代码只是初步编码完成，还未进行测试

## 待开发项
- 制作helm包
- 支持containerd/k8s版本升级为1.25
- 推送镜像后节点镜像清理
