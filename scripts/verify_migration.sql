-- scripts/verify_migration.sql
-- 验证迁移前后的数据完整性

SELECT 'Roles Count' AS metric, COUNT(*) AS count FROM roles
UNION ALL
SELECT 'Permissions Count', COUNT(*) FROM permissions
UNION ALL
SELECT 'User Roles Count', COUNT(*) FROM user_roles
UNION ALL
SELECT 'Role Permissions Count', COUNT(*) FROM role_permissions
UNION ALL
SELECT 'Casbin Rules Count', COUNT(*) FROM casbin_rule;

-- 验证所有角色都有 Casbin 策略
SELECT 
    r.id,
    r.name,
    COUNT(cr.id) AS casbin_policy_count
FROM roles r
LEFT JOIN casbin_rule cr ON cr.v0 = CAST(r.id AS CHAR)
GROUP BY r.id, r.name
HAVING COUNT(cr.id) = 0;