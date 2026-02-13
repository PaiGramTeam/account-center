package config

import (
	"fmt"
	"strings"
	"sync"

	"github.com/spf13/viper"
)

// Config aggregates application configuration sections.
type Config struct {
	App       AppConfig       `mapstructure:"app"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Auth      AuthConfig      `mapstructure:"auth"`
	Redis     RedisConfig     `mapstructure:"redis"`
	GRPC      GRPCConfig      `mapstructure:"grpc"`
	RateLimit RateLimitConfig `mapstructure:"rate_limit"`
	Email     EmailConfig     `mapstructure:"email"`
	Security  SecurityConfig  `mapstructure:"security"`
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
	AutoSeed      bool   `mapstructure:"auto_seed"`
}

// AuthConfig holds configuration for authentication flows.
type AuthConfig struct {
	AccessTokenTTLSeconds         int                            `mapstructure:"access_token_ttl"`
	RefreshTokenTTLSeconds        int                            `mapstructure:"refresh_token_ttl"`
	SessionUpdateAgeSeconds       int                            `mapstructure:"session_update_age"` // Auto-refresh threshold
	SessionFreshAgeSeconds        int                            `mapstructure:"session_fresh_age"`  // Freshness requirement for sensitive ops
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

// GRPCConfig holds gRPC server configuration.
type GRPCConfig struct {
	Enabled               bool `mapstructure:"enabled"`
	Port                  int  `mapstructure:"port"`
	MaxConnectionIdle     int  `mapstructure:"max_connection_idle"`
	MaxConnectionAge      int  `mapstructure:"max_connection_age"`
	MaxConnectionAgeGrace int  `mapstructure:"max_connection_age_grace"`
	KeepAliveTime         int  `mapstructure:"keepalive_time"`
	KeepAliveTimeout      int  `mapstructure:"keepalive_timeout"`
}

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Enabled bool                `mapstructure:"enabled"`
	Auth    RateLimitAuthConfig `mapstructure:"auth"`
	API     RateLimitAPIConfig  `mapstructure:"api"`
}

// RateLimitAuthConfig holds rate limits for authentication endpoints.
type RateLimitAuthConfig struct {
	Login        string `mapstructure:"login"`
	Register     string `mapstructure:"register"`
	VerifyEmail  string `mapstructure:"verify_email"`
	RefreshToken string `mapstructure:"refresh_token"`
	OAuth        string `mapstructure:"oauth"`
}

// RateLimitAPIConfig holds rate limits for API endpoints.
type RateLimitAPIConfig struct {
	Authenticated   string `mapstructure:"authenticated"`
	Unauthenticated string `mapstructure:"unauthenticated"`
}

// EmailConfig holds email service configuration.
type EmailConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	Provider      string `mapstructure:"provider"`      // smtp, sendgrid, mailgun, etc.
	SMTPHost      string `mapstructure:"smtp_host"`     // e.g., smtp.gmail.com
	SMTPPort      int    `mapstructure:"smtp_port"`     // e.g., 587
	SMTPUsername  string `mapstructure:"smtp_username"` // e.g., user@example.com
	SMTPPassword  string `mapstructure:"smtp_password"`
	FromEmail     string `mapstructure:"from_email"`     // Sender email address
	FromName      string `mapstructure:"from_name"`      // Sender name
	UseTLS        bool   `mapstructure:"use_tls"`        // Use TLS
	UseAsyncQueue bool   `mapstructure:"use_async"`      // Enable async sending queue
	QueueSize     int    `mapstructure:"queue_size"`     // Queue size for async sending
	Timeout       int    `mapstructure:"timeout"`        // SMTP timeout in seconds
	RetryAttempts int    `mapstructure:"retry_attempts"` // Number of retry attempts
	RetryDelay    int    `mapstructure:"retry_delay"`    // Delay between retries in seconds
	TemplateDir   string `mapstructure:"template_dir"`   // Directory for email templates (optional, uses embedded if empty)
}

// SecurityConfig holds security-related configuration.
type SecurityConfig struct {
	SuspiciousLoginDetection  bool   `mapstructure:"suspicious_login_detection"`   // Enable suspicious login detection
	SuspiciousLoginEmailAlert bool   `mapstructure:"suspicious_login_email_alert"` // Send email alerts for suspicious logins
	SecuritySettingsURL       string `mapstructure:"security_settings_url"`        // URL to account security settings page
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
	v.SetDefault("database.auto_seed", true)

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

	v.SetDefault("rate_limit.enabled", true)
	v.SetDefault("rate_limit.auth.login", "5-M")
	v.SetDefault("rate_limit.auth.register", "3-H")
	v.SetDefault("rate_limit.auth.verify_email", "10-H")
	v.SetDefault("rate_limit.auth.refresh_token", "10-M")
	v.SetDefault("rate_limit.auth.oauth", "10-M")
	v.SetDefault("rate_limit.api.authenticated", "1000-H")
	v.SetDefault("rate_limit.api.unauthenticated", "100-H")

	v.SetDefault("email.enabled", false)
	v.SetDefault("email.provider", "smtp")
	v.SetDefault("email.smtp_host", "smtp.gmail.com")
	v.SetDefault("email.smtp_port", 587)
	v.SetDefault("email.from_email", "noreply@paigram.com")
	v.SetDefault("email.from_name", "PaiGram")
	v.SetDefault("email.use_tls", true)
	v.SetDefault("email.use_async", true)
	v.SetDefault("email.retry_attempts", 3)
	v.SetDefault("email.retry_delay", 5)
}
