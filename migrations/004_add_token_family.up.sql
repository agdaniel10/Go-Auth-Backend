ALTER TABLE tokens ADD COLUMN family_id UUID NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE tokens ADD COLUMN parent_id INT REFERENCES tokens(id) ON DELETE SET NULL;

CREATE INDEX idx_tokens_family_id ON tokens(family_id);
CREATE INDEX idx_tokens_user_id ON tokens(user_id);