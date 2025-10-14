//go:build !debug
// +build !debug

package router

import "github.com/gin-gonic/gin"

func registerSwagger(_ *gin.Engine) {}
