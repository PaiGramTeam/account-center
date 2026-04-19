package platformbinding

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"paigram/internal/model"
)

func TestListGrantsPaginatesResults(t *testing.T) {
	db := setupPlatformBindingTestDB(t)
	service := NewGrantService(db)
	owner := model.User{PrimaryLoginType: model.LoginTypeEmail, Status: model.UserStatusActive}
	require.NoError(t, db.Create(&owner).Error)
	binding := model.PlatformAccountBinding{
		OwnerUserID:        owner.ID,
		Platform:           "mihomo",
		ExternalAccountKey: ns("cn:grants"),
		PlatformServiceKey: "mihomo",
		DisplayName:        "Grant List",
		Status:             model.PlatformAccountBindingStatusActive,
	}
	require.NoError(t, db.Create(&binding).Error)

	for _, consumer := range []string{"paigram-bot", "pamgram", "mihomo.sync"} {
		require.NoError(t, db.Create(&model.ConsumerGrant{
			BindingID: binding.ID,
			Consumer:  consumer,
			Status:    model.ConsumerGrantStatusActive,
		}).Error)
	}

	items, total, err := service.ListGrants(binding.ID, ListParams{Page: 2, PageSize: 1})
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
	require.Len(t, items, 1)

	ownerItems, ownerTotal, err := service.ListGrantsForOwner(owner.ID, binding.ID, ListParams{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Equal(t, int64(3), ownerTotal)
	require.Len(t, ownerItems, 2)
}
