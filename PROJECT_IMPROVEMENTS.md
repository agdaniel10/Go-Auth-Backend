# Go Auth Backend Improvements Roadmap

This document lists recommended improvements, security hardening tasks, and feature additions for the current Go authentication backend.

## Current Understanding

The project is a Go/PostgreSQL authentication API with:

- User registration and login.
- JWT access tokens.
- Database-backed refresh tokens.
- Refresh token rotation.
- Password reset using emailed 6-digit codes.
- Resend email integration.
- Protected `GET /users/me` endpoint.
- SQL migrations for users, refresh tokens, and password reset tokens.

The overall structure is good for an early backend: `cmd/api` starts the app, `internal/handlers` owns HTTP handlers, `internal/users`, `internal/tokens`, and `internal/passwordreset` contain domain logic, and `config` manages database setup.

## Critical Build Fixes

- [ ] Add a valid package declaration to `cmd/api/routes.go`, or remove the file if it is not needed.
- [ ] Fix `fmt.Errorf("user with id %w not found", userID)` in `internal/users/repository.go`; `%w` is only for wrapping errors. Use `%d` or `%v`.
- [ ] Fix `GetUsers` in `internal/users/repository.go`; it selects 4 columns but scans 5 fields.
- [ ] Run `go test ./...` and make sure the entire project builds cleanly.
- [ ] Resolve the local Go build cache permission issue if it continues blocking test runs.

## High-Priority Security Improvements

- [ ] Protect `POST /auth/logout` with authentication middleware.
- [ ] Stop accepting `user_id` from the logout request body. Use the authenticated user ID from the JWT context instead.
- [ ] Replace `math/rand` in password reset token generation with `crypto/rand`.
- [ ] Remove `fmt.Println(rawToken)` from password reset logic so reset codes are never printed to logs.
- [ ] Do not reveal whether an email exists during forgot-password requests. Always return a generic success message.
- [ ] Add rate limiting to login, register, forgot-password, reset-password, and refresh endpoints.
- [ ] Add brute-force protection for password reset codes.
- [ ] Add expiry cleanup for old refresh tokens and password reset tokens.
- [ ] Invalidate all password reset tokens for a user after a successful password reset.
- [ ] Invalidate existing refresh tokens after a password reset.
- [ ] Validate `JWT_SECRET` length and strength at startup.
- [ ] Never commit `.env` files or secrets. Confirm `.env` is ignored by Git.
- [ ] Consider storing refresh tokens with metadata such as device, IP, user agent, and last used time.

## Authentication and Token Improvements

- [ ] Add refresh token reuse detection. If an old rotated refresh token is used again, revoke all sessions for that user.
- [ ] Store only hashed refresh tokens, which the project already does. Keep this pattern.
- [ ] Add token family/session identifiers so refresh token rotation can be audited.
- [ ] Add support for logging out a single session versus all sessions.
- [ ] Add `POST /auth/logout-all` for revoking every active refresh token for the authenticated user.
- [ ] Add optional email verification before allowing full account access.
- [ ] Add password change endpoint for authenticated users.
- [ ] Require current password when changing password from an authenticated session.
- [ ] Add account lockout or temporary throttling after repeated failed login attempts.
- [ ] Add JWT issuer and audience claims.
- [ ] Add configurable access token and refresh token lifetimes.

## Password Reset Improvements

- [ ] Normalize email before looking up a user in forgot-password.
- [ ] Delete older reset codes before creating a new one for the same user.
- [ ] Limit how often a user can request a password reset email.
- [ ] Use a longer reset token or a secure one-time link if this will be used in production.
- [ ] Return specific internal errors to logs, but generic messages to clients.
- [ ] Add a clear reset email template with expiration time.
- [ ] Add a database index on `password_reset_tokens.user_id`.
- [ ] Add a database index on `password_reset_tokens.expires_at`.
- [ ] Add a background cleanup job or scheduled task for expired reset tokens.

## User Data and Validation Improvements

- [ ] Normalize emails consistently before register, login, and forgot-password.
- [ ] Add stronger password rules if needed: uppercase, lowercase, number, symbol, or compromised-password checks.
- [ ] Add request size limits to prevent large JSON bodies.
- [ ] Use `json.Decoder.DisallowUnknownFields()` for stricter API inputs.
- [ ] Add consistent validation response format.
- [ ] Avoid exposing `Password` in the `User` JSON struct by using `json:"-"`.
- [ ] Add username/name length limits.
- [ ] Add email length limits.
- [ ] Add database constraints matching application validation.

## HTTP and API Improvements

- [ ] Add a health check endpoint: `GET /health`.
- [ ] Add a readiness endpoint that checks database connectivity: `GET /ready`.
- [ ] Add JSON error responses instead of plain `http.Error` text.
- [ ] Standardize response shapes across all handlers.
- [ ] Use correct status codes. For example, `GET /users/me` should usually return `200 OK`, not `202 Accepted`.
- [ ] Fix `GetMe` so lookup errors always write an HTTP response.
- [ ] Add method-safe route grouping in `cmd/api/routes.go`.
- [ ] Move route setup out of `main.go` into a dedicated router function.
- [ ] Add CORS middleware if the API will be called from a browser app.
- [ ] Implement the placeholder rate limit middleware.
- [ ] Add request logging middleware.
- [ ] Add panic recovery middleware.
- [ ] Add graceful shutdown for the HTTP server.
- [ ] Configure server timeouts: read timeout, write timeout, idle timeout, and header timeout.

## Database and Migration Improvements

- [ ] Rename duplicate migration numbers. Both token migrations currently use `002`.
- [ ] Add indexes for common lookups:
  - [ ] `users.email`
  - [ ] `tokens.user_id`
  - [ ] `tokens.token_hash`
  - [ ] `tokens.expires_at`
  - [ ] `password_reset_tokens.user_id`
  - [ ] `password_reset_tokens.token_hash`
  - [ ] `password_reset_tokens.expires_at`
- [ ] Add down migrations if using a migration tool that supports them.
- [ ] Add a migration runner or document how migrations are applied.
- [ ] Add database connection pool settings.
- [ ] Add context timeouts around database operations.
- [ ] Consider using transactions for multi-step auth operations such as refresh token rotation and password reset.
- [ ] Make refresh token rotation atomic so deleting and creating tokens cannot leave the user without a valid session if one step fails.

## Email Improvements

- [ ] Do not make user registration fail just because the welcome email fails.
- [ ] Consider sending welcome emails asynchronously.
- [ ] Deduplicate `SendEmail` and `SendResetToken`; they currently do almost the same thing.
- [ ] Move sender address into configuration.
- [ ] Add email templates for welcome, password reset, and email verification.
- [ ] Add retry logic or queue support for email sending.
- [ ] Add email delivery logging without exposing secrets or reset codes.

## Configuration Improvements

- [ ] Centralize config loading in one config package.
- [ ] Validate all required environment variables at startup.
- [ ] Add support for environment-specific config: development, test, production.
- [ ] Add configurable server port, token TTLs, email sender, allowed CORS origins, and database pool settings.
- [ ] Provide a `.env.example` file with safe placeholder values.
- [ ] Keep `.env` out of Git.

## Observability and Logging

- [ ] Add structured logging.
- [ ] Log request ID, method, path, status, duration, and user ID when available.
- [ ] Add request ID middleware.
- [ ] Avoid logging passwords, tokens, reset codes, authorization headers, or secrets.
- [ ] Add audit logs for login, logout, password reset, password change, and refresh token reuse detection.
- [ ] Add basic metrics for request count, latency, auth failures, and email failures.

## Testing Improvements

- [ ] Add unit tests for user validation.
- [ ] Add unit tests for password hashing and verification.
- [ ] Add unit tests for JWT creation and validation.
- [ ] Add unit tests for refresh token hashing and rotation.
- [ ] Add unit tests for password reset token creation and validation.
- [ ] Add handler tests for register, login, refresh, logout, forgot-password, reset-password, and users/me.
- [ ] Add repository integration tests with a test Postgres database.
- [ ] Add tests for duplicate email handling.
- [ ] Add tests for expired refresh tokens.
- [ ] Add tests for expired reset tokens.
- [ ] Mock email sending in tests.
- [ ] Add CI to run formatting, vetting, and tests.

## Code Quality Improvements

- [ ] Run `gofmt` on all Go files.
- [ ] Run `go vet ./...`.
- [ ] Remove empty placeholder files or give them a proper purpose.
- [ ] Use consistent naming: `passwordreset` versus `password reset`.
- [ ] Fix typos in error messages such as `hask`.
- [ ] Reduce duplicated interfaces where possible.
- [ ] Keep interfaces close to the consumer, but remove unused interface methods.
- [ ] Use sentinel errors where handlers need to distinguish client errors from server errors.
- [ ] Avoid returning raw database errors directly from services.
- [ ] Consider adding a small response helper for JSON and error responses.

## New Features to Add

- [ ] Email verification flow.
- [ ] Resend verification email endpoint.
- [ ] Authenticated password change endpoint.
- [ ] Profile update endpoint.
- [ ] Delete account endpoint.
- [ ] Logout from current device.
- [ ] Logout from all devices.
- [ ] List active sessions/devices.
- [ ] Revoke a specific session.
- [ ] Admin user listing endpoint.
- [ ] Admin user disable/enable endpoint.
- [ ] Role-based access control.
- [ ] Permissions system if roles become too limited.
- [ ] Two-factor authentication using TOTP.
- [ ] Backup recovery codes for two-factor authentication.
- [ ] Login notification emails.
- [ ] Suspicious login detection.
- [ ] Account lockout after repeated failed login attempts.
- [ ] Soft delete for users.
- [ ] API documentation using OpenAPI/Swagger.
- [ ] Dockerfile and Docker Compose for local development.
- [ ] Seed script for local development.

## Suggested Implementation Order

1. Fix build errors and make `go test ./...` pass.
2. Protect logout and remove client-controlled `user_id`.
3. Secure password reset token generation and remove reset-code logging.
4. Normalize email handling across register, login, and password reset.
5. Add JSON error response helpers.
6. Add server timeouts, request logging, recovery, CORS, and rate limiting.
7. Add tests for the main auth flows.
8. Improve migrations, indexes, and token cleanup.
9. Add email verification and authenticated password change.
10. Add session management and admin/user management features.

## Production Readiness Checklist

- [ ] Project builds cleanly.
- [ ] Tests cover core auth behavior.
- [ ] Secrets are not committed.
- [ ] Auth endpoints are rate-limited.
- [ ] Password reset does not leak account existence.
- [ ] Tokens and reset codes are never logged.
- [ ] Logout requires authentication.
- [ ] Database has useful indexes.
- [ ] Server has timeouts and graceful shutdown.
- [ ] Email failures are handled safely.
- [ ] CORS is configured intentionally.
- [ ] Logs are structured and do not contain secrets.
- [ ] Migrations are ordered and documented.
- [ ] API responses are consistent.

