package scopes

import (
	"context"
	"fmt"

	commonv1 "buf.build/gen/go/charmmtech/common/protocolbuffers/go/charmmtech/common/v1"
	"github.com/charmmtech/nextools"
	"gorm.io/gorm"
)

// WithTenantScope returns a GORM scope function that filters database queries based on tenant-specific
// context values. It extracts country and state from the provided context using nextools keys and applies
// them as WHERE clauses to the query. If a country or state is not present in the context, those filters
// are not applied.
//
// Parameters:
//   - ctx: The context containing tenant information (country and state)
//
// Returns:
//   - A function that takes a *gorm.DB and returns a *gorm.DB with tenant scoping applied
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

// WithPaginationScope returns a GORM scope function that applies pagination, sorting, and ordering to database queries.
// It handles page-based pagination with configurable limits and offsets, and supports sorting by specified fields
// with ascending or descending order. Default values are applied when pagination parameters are invalid or missing.
//
// Default behavior:
//   - Page defaults to 1 if not provided or <= 0
//   - Limit defaults to 20 if not provided or <= 0
//   - Sort field defaults to "{table}.created_at" if not provided
//   - the Sort direction defaults to "desc" if not specified or invalid
//
// Parameters:
//   - pagination: The page request containing page number, limit, sort field, and sort direction
//   - table: The table name used for constructing the default sort field
//
// Returns:
//   - A function that takes a *gorm.DB and returns a *gorm.DB with pagination and sorting applied
func WithPaginationScope(pagination *commonv1.PageRequest, table string) func(db *gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		// Defaults
		page := pagination.GetPage()
		if page <= 0 {
			page = 1
		}

		limit := pagination.GetLimit()
		if limit <= 0 {
			limit = 20
		}

		offset := (page - 1) * limit

		// Apply limit and offset
		db = db.Limit(int(limit)).Offset(int(offset))

		// Sorting
		sort := pagination.GetSort()
		direction := pagination.GetDirection()

		if sort == "" {
			sort = fmt.Sprintf("%s.created_at", table)
		}

		order := "desc"
		switch direction {
		case commonv1.SortDirection_SORT_DIRECTION_ASC:
			order = "asc"
		case commonv1.SortDirection_SORT_DIRECTION_DESC:
			order = "desc"
		}

		db = db.Order(fmt.Sprintf("%s %s", sort, order))

		return db
	}
}
