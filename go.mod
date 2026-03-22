module github.com/charmmtech/nextools

go 1.24.5

require (
	connectrpc.com/connect v1.19.0
	connectrpc.com/cors v0.1.0
	connectrpc.com/grpchealth v1.4.0
	connectrpc.com/validate v0.6.0
	github.com/charmmtech/sseor v0.0.2
	github.com/coreos/go-oidc/v3 v3.15.0
	github.com/joho/godotenv v1.5.1
	github.com/nats-io/nats.go v1.45.0
	github.com/redis/go-redis/v9 v9.12.1
	github.com/rs/cors v1.11.1
	golang.org/x/net v0.43.0
	google.golang.org/grpc v1.75.0
	gorm.io/driver/postgres v1.6.0
	gorm.io/driver/sqlite v1.6.0
	gorm.io/gorm v1.30.3
)

require (
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.9-20250912141014-52f32327d4b0.1 // indirect
	buf.build/go/protovalidate v1.0.0 // indirect
	cel.dev/expr v0.24.0 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/go-jose/go-jose/v4 v4.1.1 // indirect
	github.com/google/cel-go v0.26.1 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.6.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/nats-io/nkeys v0.4.11 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/stoewer/go-strcase v1.3.1 // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/exp v0.0.0-20250911091902-df9299821621 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250922171735-9219d122eba9 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250922171735-9219d122eba9 // indirect
	google.golang.org/protobuf v1.36.9 // indirect
)

// Local replacements for charmmtech modules
replace (
	github.com/charmmtech/billing => ../billing
	github.com/charmmtech/campaign => ../campaign
	github.com/charmmtech/file => ../file
	github.com/charmmtech/gateway => ../gateway
	github.com/charmmtech/identity => ../identity
	github.com/charmmtech/influencer => ../influencer
	github.com/charmmtech/inventory => ../inventory
	github.com/charmmtech/nexor => ../nexor
	github.com/charmmtech/nextools => ../nextools
	github.com/charmmtech/notification => ../notification
	github.com/charmmtech/product => ../product
	github.com/charmmtech/setting => ../setting
	github.com/charmmtech/social => ../social
	github.com/charmmtech/sseor => ../sseor
	github.com/charmmtech/sticker => ../sticker
	github.com/charmmtech/supplier => ../supplier
	github.com/charmmtech/tax => ../tax
	github.com/charmmtech/taxonomy => ../taxonomy
	github.com/charmmtech/tenant => ../tenant
	github.com/charmmtech/transaction => ../transaction
	github.com/charmmtech/wallet => ../wallet
	github.com/charmmtech/workflow => ../workflow
)
