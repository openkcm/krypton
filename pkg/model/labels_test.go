package model_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/model"
)

func TestLabelsString(t *testing.T) {
	assert.Empty(t, model.Labels(nil).String())
	assert.Equal(t, "a=1,b=2", model.Labels{"b": "2", "a": "1"}.String())
}

func TestIsReservedKey(t *testing.T) {
	assert.True(t, model.IsReservedKey("krypton:origin"))
	assert.True(t, model.IsReservedKey(model.ReservedLabelPrefix))
	assert.False(t, model.IsReservedKey("origin"))
	// The orbital slash-form prefix is a different namespace and is not reserved here.
	assert.False(t, model.IsReservedKey("krypton/action-target-id"))
	assert.False(t, model.IsReservedKey(""))
}

func TestLabelsHasReserved(t *testing.T) {
	t.Run("returns false when no reserved keys", func(t *testing.T) {
		k, ok := model.Labels{"env": "prod", "region": "eu"}.HasReserved()
		assert.False(t, ok)
		assert.Empty(t, k)
	})

	t.Run("returns false for nil labels", func(t *testing.T) {
		k, ok := model.Labels(nil).HasReserved()
		assert.False(t, ok)
		assert.Empty(t, k)
	})

	t.Run("detects a reserved key", func(t *testing.T) {
		k, ok := model.Labels{"krypton:origin": "root"}.HasReserved()
		assert.True(t, ok)
		assert.Equal(t, "krypton:origin", k)
	})
}
