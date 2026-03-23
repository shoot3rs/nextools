package scopes

import (
	"context"

	"github.com/charmmtech/nextools"
	"gorm.io/gorm"
)

func WithTenantScope(ctx context.Context) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		country := ctx.Value(nextools.XCountryKey)
		state := ctx.Value(nextools.XStateKey)

		if country != nil {
			db.Where("country = ?", country)
		}

		if state != nil {
			db = db.Where("state = ?", state)
		}

		return db
	}
}
