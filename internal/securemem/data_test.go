package securemem_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/securemem"
)

func TestNewWithSize(t *testing.T) {
	t.Run("should create vault with specified size", func(t *testing.T) {
		// given when
		subj, err := securemem.NewData("test-region", 64)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// then
		data := subj.SecureBytes()
		assert.Len(t, data, 64)

		// mmap'd anonymous memory should be zeroed
		for _, b := range data {
			assert.Equal(t, byte(0), b)
		}
	})

	t.Run("should return error for invalid sizes", func(t *testing.T) {
		tts := []struct {
			name string
			size int
		}{
			{name: "negative size", size: -1},
			{name: "zero size", size: 0},
		}

		for _, tt := range tts {
			t.Run("for "+tt.name, func(t *testing.T) {
				// given when
				subj, err := securemem.NewData("test-"+tt.name, tt.size)

				// then
				assert.ErrorIs(t, err, securemem.ErrInvalidSize)
				assert.Nil(t, subj)
			})
		}
	})

	t.Run("should write data and read it back", func(t *testing.T) {
		// given
		secret := []byte("my-secret-key-1234567890")
		subj, err := securemem.NewData("test-roundtrip", len(secret))
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// when
		copy(subj.SecureBytes(), secret)

		// then
		assert.Equal(t, securemem.SecureBytes(secret), subj.SecureBytes())
	})

	t.Run("should allocate larger sizes", func(t *testing.T) {
		// given
		expectedSize := 5000

		// when
		subj, err := securemem.NewData("test-large-region", expectedSize)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// then
		data := subj.SecureBytes()
		assert.Len(t, data, expectedSize)

		for _, b := range data {
			assert.Equal(t, byte(0), b)
		}
	})
}

func TestAvoidLogSecureBytesPrints(t *testing.T) {
	// given
	secret := []byte("super-secret-key")
	data, err := securemem.NewData("test-key", len(secret))
	require.NoError(t, err)

	t.Cleanup(func() {
		err := data.Destroy()
		assert.NoError(t, err)
	})

	copy(data.SecureBytes(), secret)

	subj := data.SecureBytes()

	t.Run("should not leak data when printing with fmt.Printf", func(t *testing.T) {
		tts := []struct {
			format string
		}{
			{format: "%s"},
			{format: "%v"},
			{format: "%+v"},
			{format: "%#v"},
		}

		for _, tt := range tts {
			t.Run(tt.format, func(t *testing.T) {
				var buf bytes.Buffer

				// when
				fmt.Fprintf(&buf, tt.format, subj)

				got, err := io.ReadAll(&buf)

				// then
				require.NoError(t, err)
				actString := string(got)
				assert.Contains(t, actString, securemem.Redacted)
				assert.NotContains(t, actString, string(secret))
			})
		}
	})

	t.Run("should not leak data in slog output", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		// when
		logger.Info("vault", "data", subj)

		got, err := io.ReadAll(&buf)

		// then
		require.NoError(t, err)
		actString := string(got)
		assert.Contains(t, actString, securemem.Redacted)
		assert.NotContains(t, actString, string(secret))
	})

	t.Run("should not leak data in MarshalJSON()", func(t *testing.T) {
		// when
		got, err := json.Marshal(subj)

		// then
		require.NoError(t, err)
		assert.True(t, json.Valid(got))

		var decoded string
		err = json.Unmarshal(got, &decoded)
		require.NoError(t, err)
		assert.Contains(t, decoded, securemem.Redacted)
		assert.NotContains(t, decoded, string(secret))
	})

	t.Run("should not leak data in MarshalText()", func(t *testing.T) {
		// when
		got, err := subj.MarshalText()

		// then
		require.NoError(t, err)
		actString := string(got)
		assert.Contains(t, actString, securemem.Redacted)
		assert.NotContains(t, actString, string(secret))
	})
}

func TestAvoidLogDataPrints(t *testing.T) {
	// given
	secret := []byte("super-secret-key")
	subj, err := securemem.NewData("test-key", len(secret))
	require.NoError(t, err)

	t.Cleanup(func() {
		err := subj.Destroy()
		assert.NoError(t, err)
	})

	copy(subj.SecureBytes(), secret)

	t.Run("should not leak data when printing with fmt.Printf", func(t *testing.T) {
		tts := []struct {
			format string
		}{
			{format: "%s"},
			{format: "%v"},
			{format: "%+v"},
			{format: "%#v"},
		}

		for _, tt := range tts {
			t.Run(tt.format, func(t *testing.T) {
				var buf bytes.Buffer

				// when
				fmt.Fprintf(&buf, tt.format, subj)

				got, err := io.ReadAll(&buf)

				// then
				require.NoError(t, err)
				actString := string(got)
				assert.Contains(t, actString, "test-key")
				assert.Contains(t, actString, securemem.Redacted)
				assert.NotContains(t, actString, string(secret))
			})
		}
	})

	t.Run("should not leak data in slog output", func(t *testing.T) {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))

		// when
		logger.Info("vault", "data", subj)

		got, err := io.ReadAll(&buf)

		// then
		require.NoError(t, err)
		actString := string(got)
		assert.Contains(t, actString, "test-key")
		assert.Contains(t, actString, securemem.Redacted)
		assert.NotContains(t, actString, string(secret))
	})

	t.Run("should not leak data in MarshalJSON()", func(t *testing.T) {
		// when
		got, err := json.Marshal(subj)

		// then
		require.NoError(t, err)
		assert.True(t, json.Valid(got))

		var decoded string
		err = json.Unmarshal(got, &decoded)
		require.NoError(t, err)
		assert.Contains(t, decoded, "test-key")
		assert.Contains(t, decoded, securemem.Redacted)
		assert.NotContains(t, decoded, string(secret))
	})

	t.Run("should not leak data in MarshalText()", func(t *testing.T) {
		// when
		got, err := subj.MarshalText()

		// then
		require.NoError(t, err)
		actString := string(got)
		assert.Contains(t, actString, "test-key")
		assert.Contains(t, actString, securemem.Redacted)
		assert.NotContains(t, actString, string(secret))
	})
}

func TestDestroy(t *testing.T) {
	t.Run("should securely destroy vault data", func(t *testing.T) {
		// given
		subj, err := securemem.NewData("test-destroy", 128)
		require.NoError(t, err)

		// when
		err = subj.Destroy()

		// then
		assert.NoError(t, err)
		assert.Nil(t, subj.SecureBytes())
	})

	t.Run("should be idempotent", func(t *testing.T) {
		// given
		subj, err := securemem.NewData("test-idempotent", 64)
		require.NoError(t, err)

		// when
		err = subj.Destroy()

		// then
		assert.NoError(t, err)

		// when
		err = subj.Destroy()

		// then
		assert.NoError(t, err)
		assert.Nil(t, subj.SecureBytes())
	})
}

func TestReadonly(t *testing.T) {
	t.Run("should set vault to readonly mode", func(t *testing.T) {
		// given
		subj, err := securemem.NewData("test-readonly", 40)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// when
		err = subj.MarkReadOnly()

		// then
		assert.NoError(t, err)
		assert.True(t, subj.IsReadOnly())
	})

	t.Run("should be idempotent", func(t *testing.T) {
		// given
		subj, err := securemem.NewData("test-readonly-idempotent", 40)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// when
		err = subj.MarkReadOnly()

		// then
		assert.NoError(t, err)
		assert.True(t, subj.IsReadOnly())

		// when
		err = subj.MarkReadOnly()

		// then
		assert.NoError(t, err)
		assert.True(t, subj.IsReadOnly())
	})

	t.Run("should destroy vault even if readonly", func(t *testing.T) {
		// given
		subj, err := securemem.NewData("test-readonly-destroy", 40)
		require.NoError(t, err)

		err = subj.MarkReadOnly()
		assert.NoError(t, err)

		assert.True(t, subj.IsReadOnly())

		// when
		err = subj.Destroy()

		// then
		assert.NoError(t, err)
	})

	t.Run("should return nil data after destroying a read-only vault", func(t *testing.T) {
		// given
		subj, err := securemem.NewData("test-nil-after-readonly-destroy", 64)
		require.NoError(t, err)

		err = subj.MarkReadOnly()
		require.NoError(t, err)

		assert.True(t, subj.IsReadOnly())

		// when
		err = subj.Destroy()
		require.NoError(t, err)

		// then
		assert.Nil(t, subj.SecureBytes())
	})

	t.Run("should preserve data after marking read-only", func(t *testing.T) {
		// given
		secret := []byte("preserve-after-readonly")
		subj, err := securemem.NewData("test-roundtrip-readonly", len(secret))
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		copy(subj.SecureBytes(), secret)

		// when
		err = subj.MarkReadOnly()
		assert.NoError(t, err)

		// then
		assert.Equal(t, securemem.SecureBytes(secret), subj.SecureBytes())
	})
}

func TestName(t *testing.T) {
	t.Run("should return vault name", func(t *testing.T) {
		// given
		name := "test-name"
		subj, err := securemem.NewData(name, 32)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// when
		got := subj.Name()

		// then
		assert.Equal(t, name, got)
	})
}

// TestSubSlicingRetainsUnderlyingMemory verifies that sub-slicing a
// securemem.Data slice produces slices that still reference the same
// underlying memory region, ensuring no hidden copies are made.
//
// This matters because securemem.Data is backed by protected memory
// (e.g., mlock'd pages). If sub-slicing triggered a copy, the derived
// slice would escape to unprotected heap memory, defeating the purpose.
//
// The test uses an interval-overlap check on raw pointers to confirm
// that any sub-slice's backing array intersects the original:
//
//	Original securemem allocation (cap=10)
//	┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
//	│ 0 │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │  ← dataByteA
//	└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
//	        ├───────────┤
//	        dataByteA[2:5]  → still points into the same region ✓
//
//	Separate heap allocation (cap=10)
//	┌───┬───┬───┬───┬───┬───┬───┬───┬───┬───┐
//	│ 0 │ 1 │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │  ← dataByteB
//	└───┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
//	        → different memory, no overlap ✗
func TestSubSlicingRetainstheUnderlyingdatastructure(t *testing.T) {
	t.Run("sub slice shares underlying array", func(t *testing.T) {
		// given
		data, err := securemem.NewData("test-data", 10)
		require.NoError(t, err)

		dataByteA := data.SecureBytes()
		for i := range dataByteA {
			dataByteA[i] = byte(i)
		}

		dataByteB := make([]byte, 10)
		for i := range dataByteB {
			dataByteB[i] = byte(i)
		}

		// sameUnderlying reports whether slices a and b overlap in memory (by capacity).
		//	Case 1: Overlap → true        Case 2: No overlap → false
		//
		//	aStart           aEnd          aStart   aEnd
		//	├────── cap(a) ──┤             ├─cap(a)─┤
		//	┌──┬──┬──┬──┬──┬──┐           ┌──┬──┬──┐
		//	│  │  │  │  │  │  │           │  │  │  │
		//	└──┴──┴──┴──┴──┴──┘           └──┴──┴──┘
		//	      ┌──┬──┬──┬──┬──┬──┐                  ┌──┬──┬──┐
		//	      │  │  │  │  │  │  │                  │  │  │  │
		//	      └──┴──┴──┴──┴──┴──┘                  └──┴──┴──┘
		//	      ├────── cap(b) ──┤                   ├─cap(b)─┤
		//	      bStart           bEnd                bStart   bEnd
		//
		//	aStart<=bEnd ✓ && bStart<=aEnd ✓    bStart<=aEnd ✗ → false
		sameUnderLying := func(a, b []byte) bool {
			if len(a) == 0 || len(b) == 0 {
				return false
			}
			aStart := unsafe.SliceData(a)
			aEnd := unsafe.Add(unsafe.Pointer(aStart), uintptr(cap(a)-1)*unsafe.Sizeof(a[0]))
			bStart := unsafe.SliceData(b)
			bEnd := unsafe.Add(unsafe.Pointer(bStart), uintptr(cap(b)-1)*unsafe.Sizeof(b[0]))

			return uintptr(unsafe.Pointer(aStart)) <= uintptr(bEnd) &&
				uintptr(unsafe.Pointer(bStart)) <= uintptr(aEnd)
		}

		// when
		assert.False(t, sameUnderLying(dataByteA, dataByteB))
		assert.True(t, sameUnderLying(dataByteA[:1], dataByteA))
		assert.True(t, sameUnderLying(dataByteA[:5][:2], dataByteA))
		assert.True(t, sameUnderLying(dataByteA[2:], dataByteA))
		assert.True(t, sameUnderLying(dataByteA[2:][:3], dataByteA))
		assert.True(t, sameUnderLying(dataByteA[2:5], dataByteA))
		assert.True(t, sameUnderLying(dataByteA[2:5][:1], dataByteA))
	})
}
