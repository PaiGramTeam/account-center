ALTER TABLE `platform_account_bindings`
    DROP FOREIGN KEY `fk_platform_account_bindings_primary_profile`;

DROP TABLE IF EXISTS `platform_account_profiles`;
