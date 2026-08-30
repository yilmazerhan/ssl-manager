DROP TABLE certificate_k8s_target;
ALTER TABLE certificate_order DROP COLUMN key_exportable;
ALTER TABLE certificate DROP COLUMN key_exportable;
