package nextools

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"
	connectcors "connectrpc.com/cors"
	"connectrpc.com/grpchealth"
	"github.com/rs/cors"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type middleware struct {
	loggR         *zap.Logger
	contextHelper ContextHelper
	authenticator Authenticator
}

type sseMiddleware struct {
	loggR         *zap.Logger
	contextHelper ContextHelper
	authenticator Authenticator
}

func (middleware *sseMiddleware) AttachSSEHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set SSE headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Cache-Control")

		next.ServeHTTP(w, r)
	}
}

func (middleware *sseMiddleware) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println("👮 [AuthMiddleware]: Authenticating request")
		authHeader := r.Header.Get("Authorization")
		ctx := r.Context()

		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// The authorization header should be in the form "Bearer <token>".
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		bearerToken := strings.Split(authHeader, " ")
		if len(bearerToken) != 2 || bearerToken[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Validate token against Redis (you can implement your own token validation logic)
		idToken, err := middleware.authenticator.GetVerifier().Verify(ctx, token)
		if err != nil {
			http.Error(w, "Failed to verify token", http.StatusUnauthorized)
			return
		}

		claims := new(Claims)
		if err := idToken.Claims(claims); err != nil {
			return
		}

		newCtx := context.WithValue(ctx, ContextKeyUser, claims)

		next.ServeHTTP(w, r.WithContext(newCtx))
	}
}

func (middleware *sseMiddleware) NamespaceMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		country := r.Header.Get("X-Country-Iso2")
		state := r.Header.Get("X-State-Iso2")
		ctx := r.Context()

		if country == "" {
			http.Error(w, "X-Country-Iso2 header required", http.StatusBadRequest)
			return
		}

		if state == "" {
			http.Error(w, "X-State-Iso2 header required", http.StatusBadRequest)
			return
		}

		newCtx := context.WithValue(ctx, XCountryKey, strings.ToUpper(country))
		newCtx = context.WithValue(newCtx, XStateKey, strings.ToUpper(state))

		next.ServeHTTP(w, r.WithContext(newCtx))
	}
}

// UnaryTenantMismatchInterceptor checks for tenant mismatches
func (middleware *middleware) UnaryTenantMismatchInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			claims := ctx.Value(ContextKeyUser).(*Claims)
			if claims.HasRole("Root") || claims.HasRole("User") {
				log.Printf("👮 [UnaryTenantMismatchInterceptor]: Skipping tenant mismatch check for role: %s with id: %s\n", claims.GetRole(), claims.Id)
				return next(ctx, request)
			}

			countryIso2, stateIso2 := middleware.contextHelper.GetTenant(ctx)
			log.Println("Checking tenant mismatch for user:", claims.Country, countryIso2)
			if countryIso2 != claims.Country {
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("tenant country mismatch"))
			}

			if claims.HasRole("Campaign Manager") && stateIso2 != "" && stateIso2 != claims.State {
				return nil, connect.NewError(connect.CodePermissionDenied, errors.New("tenant region mismatch"))
			}

			return next(ctx, request)
		}
	}
}

// UnaryTokenInterceptor checks and parses JWT tokens and adds claims to context
func (middleware *middleware) UnaryTokenInterceptor(routes ...string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			fullMethod := req.Spec().Procedure
			if slices.Contains(routes, fullMethod) {
				return next(ctx, req)
			}

			token, err := middleware.authenticator.ExtractHeaderToken(req)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("missing or invalid token: %v", err))
			}

			idToken, err := middleware.authenticator.GetVerifier().Verify(ctx, token)
			if err != nil {
				return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("invalid token: %v", err))
			}

			claims := new(Claims)
			if err := idToken.Claims(claims); err != nil {
				return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to parse token claims: %v", err))
			}

			newCtx := context.WithValue(ctx, ContextKeyUser, claims)
			return next(newCtx, req)
		}
	}
}

// LoggingUnaryInterceptor logs sanitized gRPC request and response data
func (middleware *middleware) LoggingUnaryInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			start := time.Now()
			fullMethod := request.Spec().Procedure

			sanitizedReq := middleware.sanitizeRequest(request)

			middleware.loggR.Info("gRPC request received",
				zap.String("method", fullMethod),
				zap.Any("request", sanitizedReq),
			)

			resp, err := next(ctx, request)
			duration := time.Since(start)

			if err != nil {
				middleware.loggR.Error("gRPC request failed",
					zap.String("method", fullMethod),
					zap.Error(err),
					zap.Duration("duration", duration),
				)
			} else {
				middleware.loggR.Info("gRPC request completed",
					zap.String("method", fullMethod),
					zap.Any("response", resp),
					zap.Duration("duration", duration),
				)
			}

			return resp, err
		}
	}
}

// TenantHeaderInterceptor validates and extracts X-Country-Iso2 and X-State-Iso2 headers
func (middleware *middleware) TenantHeaderInterceptor(routes ...string) connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			fullMethod := request.Spec().Procedure
			if slices.Contains(routes, fullMethod) {
				return next(ctx, request)
			}

			country := request.Header().Get(XCountryKey)
			if country == "" {
				return nil, status.Errorf(codes.InvalidArgument, "missing required X-Country-Iso2 header")
			}

			newCtx := context.WithValue(ctx, XCountryKey, country)

			claims := middleware.contextHelper.GetUserClaims(ctx)
			if claims.HasRole("Campaign Manager") {
				state := request.Header().Get(XStateKey)
				if state == "" {
					return nil, status.Errorf(codes.InvalidArgument, "missing required X-State-Iso2 header")
				}
				newCtx = context.WithValue(newCtx, XStateKey, state)
			}

			if claims.HasRole("User") {
				if state := request.Header().Get(XStateKey); state != "" {
					newCtx = context.WithValue(newCtx, XStateKey, state)
				}
			}

			return next(newCtx, request)
		}
	}
}

// CorsMiddleware sets CORS configuration for HTTP server
func (middleware *middleware) CorsMiddleware(h http.Handler) http.Handler {
	c := cors.New(cors.Options{
		AllowedOrigins:       []string{"*"},
		AllowedMethods:       connectcors.AllowedMethods(),
		AllowedHeaders:       []string{"*"},
		ExposedHeaders:       connectcors.ExposedHeaders(),
		AllowCredentials:     false,
		OptionsSuccessStatus: 200,
	})
	return c.Handler(h)
}

// HealthChecker returns a static gRPC health checker
func (middleware *middleware) HealthChecker(srvName string) *grpchealth.StaticChecker {
	return grpchealth.NewStaticChecker(srvName)
}

// sanitizeRequest masks sensitive fields in request struct
func (middleware *middleware) sanitizeRequest(req interface{}) interface{} {
	sensitiveFields := map[string]struct{}{
		"password": {},
		"token":    {},
		"secret":   {},
		"apikey":   {},
		"apiKey":   {},
		"auth":     {},
	}
	return sanitize(req, sensitiveFields)
}

func sanitize(v interface{}, sensitiveFields map[string]struct{}) interface{} {
	if v == nil {
		return nil
	}

	rv := reflect.ValueOf(v)
	rt := reflect.TypeOf(v)

	if rv.Kind() == reflect.Ptr && !rv.IsNil() {
		rv = rv.Elem()
		rt = rt.Elem()
	}

	if rv.Kind() != reflect.Struct {
		return v
	}

	copied := reflect.New(rt).Elem()
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		value := rv.Field(i)
		fieldName := strings.ToLower(field.Name)

		if !value.CanInterface() {
			continue
		}

		if _, isSensitive := sensitiveFields[fieldName]; isSensitive {
			if field.Type.Kind() == reflect.String {
				copied.Field(i).SetString("[REDACTED]")
			} else {
				copied.Field(i).Set(reflect.Zero(field.Type))
			}
		} else if field.Type.Kind() == reflect.Struct {
			sanitized := sanitize(value.Interface(), sensitiveFields)
			copied.Field(i).Set(reflect.ValueOf(sanitized))
		} else {
			copied.Field(i).Set(value)
		}
	}
	return copied.Addr().Interface()
}

// NewMiddleware returns a new instance of middleware
func NewMiddleware(authenticator Authenticator, logger *zap.Logger, contextHelper ContextHelper) Middleware {
	return &middleware{
		loggR:         logger,
		authenticator: authenticator,
		contextHelper: contextHelper,
	}
}

func NewSseMiddleware(authenticator Authenticator, logger *zap.Logger, contextHelper ContextHelper) SSEMiddleware {
	return &sseMiddleware{
		loggR:         logger,
		contextHelper: contextHelper,
		authenticator: authenticator,
	}
}
