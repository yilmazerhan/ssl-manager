-- Subject fields beyond CommonName/SANs (organization, organizational
-- unit, country, state, locality) — collected on the order so the CSR
-- carries them, and copied onto the issued certificate so a renewal (which
-- reuses the existing key and SANs, see order.Service.CreateRenewal) can
-- carry the same subject forward without asking again.
ALTER TABLE certificate_order
    ADD COLUMN organization text,
    ADD COLUMN organizational_unit text,
    ADD COLUMN country text,
    ADD COLUMN state text,
    ADD COLUMN locality text;

ALTER TABLE certificate
    ADD COLUMN organization text,
    ADD COLUMN organizational_unit text,
    ADD COLUMN country text,
    ADD COLUMN state text,
    ADD COLUMN locality text;
