ALTER TABLE certificate_order DROP CONSTRAINT certificate_order_ca_provider_check;
ALTER TABLE certificate_order ADD CONSTRAINT certificate_order_ca_provider_check
    CHECK (ca_provider IN ('letsencrypt', 'zerossl'));

ALTER TABLE certificate DROP CONSTRAINT certificate_ca_provider_check;
ALTER TABLE certificate ADD CONSTRAINT certificate_ca_provider_check
    CHECK (ca_provider IN ('letsencrypt', 'zerossl', 'manual'));
