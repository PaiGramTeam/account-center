package config

import (
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

// Config aggregates application configuration sections.
type Config struct {
	App      AppConfig      `mapstructure:"app"`
	Database DatabaseConfig `mapstructure:"database"`
	Auth     AuthConfig     `mapstructure:"auth"`
	Redis    RedisConfig    `mapstructure:"redis"`
}

// AppConfig holds HTTP server configuration.
type AppConfig struct {
	Name string `mapstructure:"name"`
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
	Mode string `mapstructure:"mode"`
}

// DatabaseConfig holds MySQL connection configuration.
type DatabaseConfig struct {
	Addr          string `mapstructure:"addr"`
	Username      string `mapstructure:"username"`
	Password      string `mapstructure:"password"`
	Dbname        string `mapstructure:"dbname"`
	Config        string `mapstructure:"config"`
	MigrationsDir string `mapstructure:"migrations_dir"`
	MaxIdleConns  int    `mapstructure:"max_idle_conns"`
	MaxOpenConns  int    `mapstructure:"max_open_conns"`
	LogMode       string `mapstructure:"log_mode"`
	LogZap        bool   `mapstructure:"log_zap"`
	SlowThreshold int    `mapstructure:"slow_threshold"`
	AutoMigrate   bool   `mapstructure:"auto_migrate"`
}

// AuthConfig holds configuration for authentication flows.
type AuthConfig struct {
	AccessTokenTTLSeconds         int                            `mapstructure:"access_token_ttl"`
	RefreshTokenTTLSeconds        int                            `mapstructure:"refresh_token_ttl"`
	EmailVerificationTTLSeconds   int                            `mapstructure:"email_verification_ttl"`
	OAuthStateTTLSeconds          int                            `mapstructure:"oauth_state_ttl"`
	AllowedOAuthProviders         []string                       `mapstructure:"allowed_providers"`
	OAuthProviders                map[string]OAuthProviderConfig `mapstructure:"oauth"`
	DefaultOAuthRedirectURL       string                         `mapstructure:"default_oauth_redirect_url"`
	MaxConcurrentSessionsPerUser  int                            `mapstructure:"max_sessions_per_user"`
	PendingUserExpirySeconds      int                            `mapstructure:"pending_user_expiry"`
	PasswordResetTokenTTLSeconds  int                            `mapstructure:"password_reset_ttl"`
	RequireEmailVerificationLogin bool                           `mapstructure:"require_verified_email_login"`
}

// OAuthProviderConfig models third-party provider credentials.
type OAuthProviderConfig struct {
	ClientID     string   `mapstructure:"client_id"`
	ClientSecret string   `mapstructure:"client_secret"`
	RedirectURL  string   `mapstructure:"redirect_url"`
	AuthURL      string   `mapstructure:"auth_url"`
	TokenURL     string   `mapstructure:"token_url"`
	UserInfoURL  string   `mapstructure:"user_info_url"`
	Scopes       []string `mapstructure:"scopes"`
}

// RedisConfig holds Redis connection and pooling behaviour.
type RedisConfig struct {
	Enabled      bool   `mapstructure:"enabled"`
	Addr         string `mapstructure:"addr"`
	Username     string `mapstructure:"username"`
	Password     string `mapstructure:"password"`
	DB           int    `mapstructure:"db"`
	Prefix       string `mapstructure:"prefix"`
	DialTimeout  int    `mapstructure:"dial_timeout"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
	PoolSize     int    `mapstructure:"pool_size"`
	MinIdleConns int    `mapstructure:"min_idle_conns"`
	MaxRetries   int    `mapstructure:"max_retries"`
}

var (
	cfg     *Config
	cfgOnce sync.Once
)

// Load initializes configuration using Viper and returns a singleton instance.
// Subsequent calls reuse the loaded configuration.
func Load(paths ...string) (*Config, error) {
	var err error
	cfgOnce.Do(func() {
		v := viper.New()
		v.SetConfigName("config")
		v.SetConfigType("yaml")

		setDefaults(v)

		if len(paths) == 0 {
			v.AddConfigPath(".")
			v.AddConfigPath("./config")
			v.AddConfigPath("./configs")
		} else {
			for _, path := range paths {
				v.AddConfigPath(path)
			}
		}

		v.SetEnvPrefix("PAI")
		v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
		v.AutomaticEnv()

		if readErr := v.ReadInConfig(); readErr != nil {
			err = fmt.Errorf("read config: %w", readErr)
			return
		}

		localCfg := &Config{}
		if unmarshalErr := v.Unmarshal(localCfg); unmarshalErr != nil {
			err = fmt.Errorf("unmarshal config: %w", unmarshalErr)
			return
		}

		cfg = localCfg
	})

	if err != nil {
		Reset()
		return nil, err
	}

	if cfg == nil {
		return nil, fmt.Errorf("configuration not loaded")
	}
	return cfg, nil
}

// MustLoad panics when configuration cannot be loaded.
func MustLoad(paths ...string) *Config {
	c, err := Load(paths...)
	if err != nil {
		panic(err)
	}
	return c
}

// Reset clears the Singleton (useful for tests).
func Reset() {
	cfg = nil
	cfgOnce = sync.Once{}
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("database.config", "charset=utf8mb4&parseTime=True&loc=Asia%2FShanghai")
	v.SetDefault("database.migrations_dir", "initialize/migrate/sql")
	v.SetDefault("database.max_idle_conns", 10)
	v.SetDefault("database.max_open_conns", 100)
	v.SetDefault("database.log_mode", "info")
	v.SetDefault("database.log_zap", true)
	v.SetDefault("database.slow_threshold", 1000)
	v.SetDefault("database.auto_migrate", true)

	v.SetDefault("auth.access_token_ttl", 900)
	v.SetDefault("auth.refresh_token_ttl", 604800)
	v.SetDefault("auth.email_verification_ttl", 86400)
	v.SetDefault("auth.oauth_state_ttl", 300)
	v.SetDefault("auth.allowed_providers", []string{"github", "google"})
	v.SetDefault("auth.default_oauth_redirect_url", "http://localhost:8080/api/v1/auth/oauth/callback")
	v.SetDefault("auth.max_sessions_per_user", 10)
	v.SetDefault("auth.pending_user_expiry", 2592000)
	v.SetDefault("auth.password_reset_ttl", 3600)
	v.SetDefault("auth.require_verified_email_login", true)

	v.SetDefault("redis.enabled", false)
	v.SetDefault("redis.addr", "127.0.0.1:6379")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.prefix", "paigram")
	v.SetDefault("redis.dial_timeout", 5)
	v.SetDefault("redis.read_timeout", 3)
	v.SetDefault("redis.write_timeout", 3)
	v.SetDefault("redis.pool_size", 20)
	v.SetDefault("redis.min_idle_conns", 5)
	v.SetDefault("redis.max_retries", 2)
}
