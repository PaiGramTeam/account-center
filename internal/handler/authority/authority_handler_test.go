package authority

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplaceAuthorityUsersRequiresAuthenticatedActor(t *testing.T) {
	gin.SetMode(gin.TestMode)

	handler := NewAuthorityHandler(nil)
	body, err := json.Marshal(ReplaceAuthorityUsersRequest{UserIDs: []uint64{1}})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Params = []gin.Param{{Key: "id", Value: "1"}}
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/authorities/1/users", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	handler.ReplaceAuthorityUsers(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "authentication required")
}
