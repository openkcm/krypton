package store_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

func TestKeyTreeTraversal(t *testing.T) {
	// given
	subj := store.KeyTree{
		{
			{ID: "A", Name: "A", Kind: "K0"},
		},
		{
			{ID: "B", Name: "B", Kind: "K1"},
			{ID: "C", Name: "C", Kind: "K1"},
		},
		{
			{ID: "D", Name: "D", Kind: "K2"},
			{ID: "E", Name: "E", Kind: "K2"},
			{ID: "F", Name: "F", Kind: "K2"},
			{ID: "G", Name: "G", Kind: "K2"},
		},
		{
			{ID: "H", Name: "H", Kind: "K3"},
		},
	}

	t.Run("IterKeysByLayerAsc should iterate layers in ascending order", func(t *testing.T) {
		// given
		expectedLayers := [][]model.Key{
			{
				{ID: "A", Name: "A", Kind: "K0"},
			},
			{
				{ID: "B", Name: "B", Kind: "K1"},
				{ID: "C", Name: "C", Kind: "K1"},
			},
			{
				{ID: "D", Name: "D", Kind: "K2"},
				{ID: "E", Name: "E", Kind: "K2"},
				{ID: "F", Name: "F", Kind: "K2"},
				{ID: "G", Name: "G", Kind: "K2"},
			},
			{
				{ID: "H", Name: "H", Kind: "K3"},
			},
		}

		i := 0
		// when
		for layer := range subj.IterKeysByLayerAsc() {
			// then
			assert.Equal(t, expectedLayers[i], layer)
			i++
		}
		assert.Equal(t, len(expectedLayers), i)
	})

	t.Run("IterKeysByLayerDsc should iterate layers in descending order", func(t *testing.T) {
		// given
		expectedLayers := [][]model.Key{
			{
				{ID: "H", Name: "H", Kind: "K3"},
			},
			{
				{ID: "D", Name: "D", Kind: "K2"},
				{ID: "E", Name: "E", Kind: "K2"},
				{ID: "F", Name: "F", Kind: "K2"},
				{ID: "G", Name: "G", Kind: "K2"},
			},
			{
				{ID: "B", Name: "B", Kind: "K1"},
				{ID: "C", Name: "C", Kind: "K1"},
			},
			{
				{ID: "A", Name: "A", Kind: "K0"},
			},
		}

		i := 0
		// when
		for layer := range subj.IterKeysByLayerDsc() {
			// then
			assert.Equal(t, expectedLayers[i], layer)
			i++
		}
		assert.Equal(t, len(expectedLayers), i)
	})

	t.Run("IterLayerAsc should iterate key kinds in ascending order", func(t *testing.T) {
		// given
		expectedKinds := []model.KeyKind{"K0", "K1", "K2", "K3"}

		i := 0
		// when
		for kind := range subj.IterLayerAsc() {
			//  then
			assert.Equal(t, expectedKinds[i], kind)
			i++
		}
		assert.Equal(t, len(expectedKinds), i)
	})

	t.Run("IterLayerDsc should iterate key kinds in descending order", func(t *testing.T) {
		// given
		expectedKinds := []model.KeyKind{"K3", "K2", "K1", "K0"}

		i := 0
		// when
		for kind := range subj.IterLayerDsc() {
			// then
			assert.Equal(t, expectedKinds[i], kind)
			i++
		}
		assert.Equal(t, len(expectedKinds), i)
	})
}
