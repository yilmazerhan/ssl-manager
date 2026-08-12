-- Supports revoking at the CA (not just marking revoked locally): ZeroSSL
-- revokes by certificate ID, which only exists as long as we keep it.
-- Let's Encrypt doesn't need this — revoking there only needs the
-- certificate body — but the column is provider-agnostic so the order
-- service doesn't need to know which CA cares.
ALTER TABLE certificate ADD COLUMN ca_reference text;
