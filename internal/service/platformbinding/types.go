package platformbinding

import (
	"database/sql"
	"time"
)

const ConsumerPaiGramBot = "paigram-bot"

var SupportedConsumers = []string{ConsumerPaiGramBot}

type CreateBindingInput struct {
	OwnerUserID        uint64
	Platform           string
	ExternalAccountKey string
	PlatformServiceKey string
	DisplayName        string
}

type UpsertGrantInput struct {
	BindingID uint64
	Consumer  string
	GrantedBy sql.NullInt64
	GrantedAt time.Time
}

type RevokeGrantInput struct {
	BindingID uint64
	Consumer  string
	RevokedAt time.Time
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
