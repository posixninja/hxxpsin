-- Insert vulns directly into the MSF Postgres database. msfconsole's
-- `vulns` command in this MSF version is read-only (it lists/filters
-- but has no -a flag — exploit modules create vuln rows). Inject them
-- via SQL so the integration tests see deterministic data.
--
-- Idempotent: WHERE NOT EXISTS guards against re-seeding duplicates.

INSERT INTO vulns (host_id, name, info, created_at, updated_at)
SELECT h.id, 'DVWA Default Credentials', 'seeded', NOW(), NOW()
FROM hosts h JOIN workspaces w ON w.id = h.workspace_id
WHERE h.address = '172.28.0.10' AND w.name = 'hxxpsin-test'
  AND NOT EXISTS (
    SELECT 1 FROM vulns v
    WHERE v.host_id = h.id AND v.name = 'DVWA Default Credentials');

INSERT INTO vulns (host_id, name, info, created_at, updated_at)
SELECT h.id, 'MySQL Anonymous Login', 'seeded', NOW(), NOW()
FROM hosts h JOIN workspaces w ON w.id = h.workspace_id
WHERE h.address = '172.28.0.10' AND w.name = 'hxxpsin-test'
  AND NOT EXISTS (
    SELECT 1 FROM vulns v
    WHERE v.host_id = h.id AND v.name = 'MySQL Anonymous Login');

SELECT v.id, v.name, h.address
FROM vulns v JOIN hosts h ON h.id = v.host_id
JOIN workspaces w ON w.id = h.workspace_id
WHERE w.name = 'hxxpsin-test';
