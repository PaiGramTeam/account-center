package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	testData := map[string]interface{}{
		"id":   1,
		"name": "test",
	}

	Success(c, testData)

	assert.Equal(t, http.StatusOK, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "success", response.Message)
	assert.NotNil(t, response.Data)

	data, ok := response.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(1), data["id"])
	assert.Equal(t, "test", data["name"])
}

func TestError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Error(c, http.StatusBadRequest, "invalid request")

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, response.Code)
	assert.Equal(t, "invalid request", response.Message)
	assert.Nil(t, response.Data)
}

func TestBadRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	BadRequest(c, "bad request")

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, http.StatusBadRequest, response.Code)
	assert.Equal(t, "bad request", response.Message)
	assert.Nil(t, response.Data)
}

func TestCreated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	testData := map[string]interface{}{
		"id": 123,
	}

	Created(c, testData)

	assert.Equal(t, http.StatusCreated, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, http.StatusCreated, response.Code)
	assert.Equal(t, "created successfully", response.Message)
	assert.NotNil(t, response.Data)
}

func TestPageData(t *testing.T) {
	list := []interface{}{
		map[string]interface{}{"id": 1, "name": "item1"},
		map[string]interface{}{"id": 2, "name": "item2"},
	}

	pageData := NewPageData(list, 100, 1, 10)

	assert.Equal(t, list, pageData.List)
	assert.Equal(t, int64(100), pageData.Total)
	assert.Equal(t, 1, pageData.Page)
	assert.Equal(t, 10, pageData.PageSize)
	assert.Equal(t, 10, pageData.TotalPages)

	// Test empty page data
	emptyData := EmptyPageData(1, 20)
	assert.Empty(t, emptyData.List)
	assert.Equal(t, int64(0), emptyData.Total)
	assert.Equal(t, 0, emptyData.TotalPages)
}

func TestMessageData(t *testing.T) {
	msgData := NewMessageData("operation successful")
	assert.Equal(t, "operation successful", msgData.Message)
}
