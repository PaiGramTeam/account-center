ALTER TABLE `users`
    DROP FOREIGN KEY `fk_users_primary_role_assignment`,
    DROP INDEX `idx_users_primary_role_assignment`,
    DROP INDEX `idx_users_primary_role_id`,
    DROP COLUMN `primary_role_id`;
