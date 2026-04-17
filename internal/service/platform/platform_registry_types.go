package platform

import (
	"errors"
	"time"
)

type ConfigState string

const (
	ConfigStateEnabled  ConfigState = "enabled"
	ConfigStateDisabled ConfigState = "disabled"
)

var (
	ErrPlatformServiceConflict      = errors.New("platform service conflict")
	ErrPlatformServiceReferenced    = errors.New("platform service is referenced")
	ErrInvalidPlatformServiceConfig = errors.New("invalid platform service config")
)

type CreatePlatformServiceInput struct {
	PlatformKey      string         `json:"platform_key"`
	DisplayName      string         `json:"display_name"`
	ServiceKey       string         `json:"service_key"`
	ServiceAudience  string         `json:"service_audience"`
	DiscoveryType    string         `json:"discovery_type"`
	Endpoint         string         `json:"endpoint"`
	Enabled          bool           `json:"enabled"`
	SupportedActions []string       `json:"supported_actions"`
	CredentialSchema map[string]any `json:"credential_schema"`
}

type UpdatePlatformServiceInput struct {
	PlatformKey      string         `json:"platform_key"`
	DisplayName      string         `json:"display_name"`
	ServiceKey       string         `json:"service_key"`
	ServiceAudience  string         `json:"service_audience"`
	DiscoveryType    string         `json:"discovery_type"`
	Endpoint         string         `json:"endpoint"`
	Enabled          bool           `json:"enabled"`
	SupportedActions []string       `json:"supported_actions"`
	CredentialSchema map[string]any `json:"credential_schema"`
}

type PlatformServiceAdminView struct {
	ID               uint64         `json:"id"`
	PlatformKey      string         `json:"platform_key"`
	DisplayName      string         `json:"display_name"`
	ServiceKey       string         `json:"service_key"`
	ServiceAudience  string         `json:"service_audience"`
	DiscoveryType    string         `json:"discovery_type"`
	Endpoint         string         `json:"endpoint"`
	Enabled          bool           `json:"enabled"`
	SupportedActions []string       `json:"supported_actions"`
	CredentialSchema map[string]any `json:"credential_schema"`
	ConfigState      ConfigState    `json:"config_state"`
	RuntimeState     RuntimeState   `json:"runtime_state"`
	CheckedAt        *time.Time     `json:"checked_at,omitempty"`
	Error            string         `json:"error,omitempty"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}
