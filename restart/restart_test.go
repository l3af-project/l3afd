package restart

import (
	"testing"

	"github.com/l3af-project/l3afd/v2/models"
)

func TestGetValueofLabel(t *testing.T) {
	b := []models.Label{
		{
			Name:  "iface",
			Value: "fakeif0",
		},
	}
	q := "iface"
	ans := "fakeif0"
	t.Run("goodtest", func(t *testing.T) {
		if ans != GetValueofLabel(q, b) {
			t.Errorf("GetValueofLabel failed")
		}
	})
}
