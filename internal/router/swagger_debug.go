//go:build debug
// +build debug

package router

import (
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/go-openapi/runtime/middleware"
)

const (
	swaggerSpecJSON = "swagger.json"
	swaggerDocsDir  = "docs"
)

func registerSwagger(r *gin.Engine) {
	specJSONPath := filepath.Join(swaggerDocsDir, swaggerSpecJSON)

	r.StaticFile("/swagger/doc.json", specJSONPath)

	uiOpts := middleware.SwaggerUIOpts{
		SpecURL: "/swagger/doc.json",
		Path:    "swagger",
	}
	ui := middleware.SwaggerUI(uiOpts, nil)
	r.GET("/swagger/*any", gin.WrapH(ui))

	redocOpts := middleware.RedocOpts{
		SpecURL: "/swagger/doc.json",
		Path:    "redoc",
	}
	redoc := middleware.Redoc(redocOpts, nil)
	r.GET("/redoc", gin.WrapH(redoc))
}
