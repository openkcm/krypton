package validator

import (
	"errors"
	"fmt"

	"github.com/openkcm/krypton/pkg/model"
)

var ErrReservedLabel = errors.New("label is reserved for internal use")

// ValidateUserLabels rejects labels reserved for Krypton's internal use.
func ValidateUserLabels(labels model.Labels) error {
	if key, ok := labels.HasReserved(); ok {
		return fmt.Errorf("%w: %s", ErrReservedLabel, key)
	}
	return nil
}
