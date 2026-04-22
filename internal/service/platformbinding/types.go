package platformbinding

import (
	"database/sql"
	"encoding/json"
	"time"

	"paigram/internal/model"
)

const (
	ConsumerPaiGramBot = model.ConsumerPaiGramBot
	ConsumerPamgram    = model.ConsumerPamgram
)

var SupportedConsumers = model.SupportedConsumers

type CreateBindingInput struct {
	OwnerUserID        uint64
	Platform           string
	ExternalAccountKey sql.NullString
	PlatformServiceKey string
	DisplayName        string
}

type CreateAndBindInput struct {
	OwnerUserID       uint64
	Platform          string
	DisplayName       string
	ActorType         string
	ActorID           string
	CredentialPayload json.RawMessage
}

type UpsertGrantInput struct {
	BindingID uint64
	Consumer  string
	GrantedBy sql.NullInt64
	GrantedAt time.Time
}

type RevokeGrantInput struct {
	BindingID   uint64
	Consumer    string
	RevokedAt   time.Time
	ActorUserID sql.NullInt64
}

type ProfileProjectionInput struct {
	PlatformProfileKey string
	GameBiz            string
	Region             string
	PlayerUID          string
	Nickname           string
	Level              sql.NullInt64
	IsPrimary          bool
	SourceUpdatedAt    sql.NullTime
}

type SyncProfilesInput struct {
	BindingID uint64
	Profiles  []ProfileProjectionInput
	SyncedAt  time.Time
}

type PutCredentialInput struct {
	OwnerUserID        uint64
	BindingID          uint64
	ActorType          string
	ActorID            string
	RequestedByAdminID uint64
	CredentialPayload  json.RawMessage
}

type RuntimeSummary struct {
	PlatformAccountID string           `json:"platform_account_id"`
	Status            string           `json:"status"`
	LastValidatedAt   any              `json:"last_validated_at"`
	LastRefreshedAt   any              `json:"last_refreshed_at"`
	Devices           []map[string]any `json:"devices"`
	Profiles          []map[string]any `json:"profiles"`
}
