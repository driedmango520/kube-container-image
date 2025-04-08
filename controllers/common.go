package controllers

import (
	"net/url"
	"strings"
)

// containsString 检查字符串切片中是否包含指定字符串
func containsString(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// removeString 从字符串切片中移除指定字符串
func removeString(slice []string, str string) []string {
	for i, s := range slice {
		if s == str {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

// ParseImageRepo 解析镜像仓库地址中的镜像仓库部分
func ParseImageRepo(imageURL string) (string, error) {
	if !strings.HasPrefix(imageURL, "http") {
		imageURL = "http://" + imageURL
	}
	u, err := url.Parse(imageURL)
	if err != nil {
		return "", err
	}
	host := u.Host
	if host == "" {
		// 如果没有协议头，尝试手动解析
		parts := strings.SplitN(imageURL, "/", 2)
		if len(parts) > 1 && strings.Contains(parts[0], ":") {
			return parts[0], nil
		}
	}
	return host, nil
}
