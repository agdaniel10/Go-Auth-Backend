ALTER TABLE users ADD COLUMN email_verified BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id         SERIAL PRIMARY KEY,
    user_id    INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);