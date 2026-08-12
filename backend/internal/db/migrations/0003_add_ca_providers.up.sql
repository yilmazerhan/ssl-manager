-- Widens the ca_provider allow-list to the two new Authority
-- implementations: selfsigned (always available, no external account) and
-- adcs (Active Directory Certificate Services via certsrv).
ALTER TABLE certificate DROP CONSTRAINT certificate_ca_provider_check;
ALTER TABLE certificate ADD CONSTRAINT certificate_ca_provider_check
    CHECK (ca_provider IN ('letsencrypt', 'zerossl', 'manual', 'selfsigned', 'adcs'));

ALTER TABLE certificate_order DROP CONSTRAINT certificate_order_ca_provider_check;
ALTER TABLE certificate_order ADD CONSTRAINT certificate_order_ca_provider_check
    CHECK (ca_provider IN ('letsencrypt', 'zerossl', 'selfsigned', 'adcs'));
