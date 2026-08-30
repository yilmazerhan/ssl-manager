ALTER TABLE discovery_result
    DROP COLUMN signature_algorithm,
    DROP COLUMN cipher_suite,
    DROP COLUMN vulnerabilities;

DROP TABLE discovery_schedule;
