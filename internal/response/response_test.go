package response

import (
	"encoding/json"
	"math"
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

func TestSuccessWithPaginationUsesItemsPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	items := []map[string]interface{}{
		{"id": 1, "name": "item1"},
		{"id": 2, "name": "item2"},
	}

	SuccessWithPagination(c, items, 2, 1, 10)

	assert.Equal(t, http.StatusOK, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	payload, ok := response.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, payload, "items")
	assert.NotContains(t, payload, "data")
	assert.NotContains(t, payload, "meta")

	itemsPayload, ok := payload["items"].([]interface{})
	require.True(t, ok)
	assert.Len(t, itemsPayload, 2)

	pagination, ok := payload["pagination"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(2), pagination["total"])
	assert.Equal(t, float64(1), pagination["page"])
	assert.Equal(t, float64(10), pagination["page_size"])
	assert.Equal(t, float64(1), pagination["total_pages"])
}

func TestSuccessWithPaginationMetaIncludesMeta(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	items := []map[string]interface{}{{"id": 1, "name": "item1"}}
	meta := map[string]interface{}{"roles": []string{"admin"}}

	SuccessWithPaginationMeta(c, items, 1, 1, 10, meta)

	assert.Equal(t, http.StatusOK, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	payload, ok := response.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, payload, "meta")

	metaPayload, ok := payload["meta"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, []interface{}{"admin"}, metaPayload["roles"])
}

func TestSuccessWithPaginationMetaOmitsMetaWhenNil(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	items := []map[string]interface{}{{"id": 1, "name": "item1"}}

	SuccessWithPaginationMeta(c, items, 1, 1, 10, nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var response Response
	err := json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)

	payload, ok := response.Data.(map[string]interface{})
	require.True(t, ok)
	assert.NotContains(t, payload, "meta")
}

func TestNewPaginationMetaReturnsZeroPagesForEmptyCollection(t *testing.T) {
	meta := NewPaginationMeta(0, 1, 20)

	require.NotNil(t, meta)
	assert.Equal(t, int64(0), meta.Total)
	assert.Equal(t, 1, meta.Page)
	assert.Equal(t, 20, meta.PageSize)
	assert.Equal(t, 0, meta.TotalPages)
}

func TestNewPaginationMetaReturnsZeroPagesForNonPositivePageSize(t *testing.T) {
	meta := NewPaginationMeta(42, 2, 0)

	require.NotNil(t, meta)
	assert.Equal(t, int64(42), meta.Total)
	assert.Equal(t, 2, meta.Page)
	assert.Equal(t, 0, meta.PageSize)
	assert.Equal(t, 0, meta.TotalPages)
}

func TestNewPaginationMetaUsesInt64ArithmeticBeforeBoundedConversion(t *testing.T) {
	total := int64(math.MaxInt32) + 18
	pageSize := 2

	meta := NewPaginationMeta(total, 1, pageSize)

	require.NotNil(t, meta)
	assert.Equal(t, total, meta.Total)
	assert.Equal(t, 1, meta.Page)
	assert.Equal(t, pageSize, meta.PageSize)
	assert.Equal(t, int((total+int64(pageSize)-1)/int64(pageSize)), meta.TotalPages)
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
