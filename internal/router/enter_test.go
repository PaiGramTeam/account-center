package router

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRouterGroupStructure(t *testing.T) {
	rg := &RouterGroup{}

	t.Run("has UserRouterGroup field", func(t *testing.T) {
		assert.NotNil(t, &rg.UserRouterGroup, "RouterGroup should have UserRouterGroup field")
	})

	t.Run("has AuthorityRouterGroup field", func(t *testing.T) {
		assert.NotNil(t, &rg.AuthorityRouterGroup, "RouterGroup should have AuthorityRouterGroup field")
	})
}

func TestRouterGroupAppExists(t *testing.T) {
	assert.NotNil(t, RouterGroupApp, "RouterGroupApp global instance should exist")
}
