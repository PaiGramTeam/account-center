ALTER TABLE `users`
    ADD COLUMN `primary_role_id` BIGINT UNSIGNED NULL AFTER `status`,
    ADD KEY `idx_users_primary_role_id` (`primary_role_id`),
    ADD KEY `idx_users_primary_role_assignment` (`id`, `primary_role_id`),
    ADD CONSTRAINT `fk_users_primary_role_assignment`
        FOREIGN KEY (`id`, `primary_role_id`) REFERENCES `user_roles` (`user_id`, `role_id`)
        ON DELETE RESTRICT ON UPDATE CASCADE;
