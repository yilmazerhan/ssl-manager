ALTER TABLE certificate_order
    DROP COLUMN organization,
    DROP COLUMN organizational_unit,
    DROP COLUMN country,
    DROP COLUMN state,
    DROP COLUMN locality;

ALTER TABLE certificate
    DROP COLUMN organization,
    DROP COLUMN organizational_unit,
    DROP COLUMN country,
    DROP COLUMN state,
    DROP COLUMN locality;
