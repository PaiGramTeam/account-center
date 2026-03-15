package router

import (
	"fmt"
	"strings"
	"time"

	gincors "github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"paigram/internal/config"
)

var (
	defaultCORSMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	defaultCORSHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
)

func newCORSMiddleware(cfg config.CORSConfig) (gin.HandlerFunc, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	if len(cfg.AllowOrigins) == 0 {
		return nil, fmt.Errorf("app.cors.allow_origins must not be empty when CORS is enabled")
	}

	hasWildcardOrigin := false
	for _, origin := range cfg.AllowOrigins {
		if strings.TrimSpace(origin) == "*" {
			hasWildcardOrigin = true
			break
		}
	}

	if hasWildcardOrigin && cfg.AllowCredentials {
		return nil, fmt.Errorf("app.cors.allow_credentials cannot be true when app.cors.allow_origins contains '*'")
	}

	allowMethods := cfg.AllowMethods
	if len(allowMethods) == 0 {
		allowMethods = defaultCORSMethods
	}

	allowHeaders := cfg.AllowHeaders
	if len(allowHeaders) == 0 {
		allowHeaders = defaultCORSHeaders
	}

	maxAge := time.Duration(cfg.MaxAgeSeconds) * time.Second
	if cfg.MaxAgeSeconds <= 0 {
		maxAge = 12 * time.Hour
	}

	corsCfg := gincors.Config{
		AllowMethods:              allowMethods,
		AllowHeaders:              allowHeaders,
		ExposeHeaders:             cfg.ExposeHeaders,
		AllowCredentials:          cfg.AllowCredentials,
		AllowWildcard:             cfg.AllowWildcard,
		AllowPrivateNetwork:       cfg.AllowPrivateNetwork,
		MaxAge:                    maxAge,
		OptionsResponseStatusCode: 204,
	}

	if hasWildcardOrigin {
		corsCfg.AllowAllOrigins = true
	} else {
		corsCfg.AllowOrigins = cfg.AllowOrigins
	}

	return gincors.New(corsCfg), nil
}
