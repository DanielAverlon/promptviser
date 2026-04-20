SELECT pg_terminate_backend (pg_stat_activity.pid)
FROM pg_stat_activity
WHERE
    pg_stat_activity.datname = 'adviserdb'
    AND pid <> pg_backend_pid ();

DROP DATABASE IF EXISTS adviserdb;

REVOKE ALL ON SCHEMA public FROM promptviser;

DROP USER IF EXISTS promptviser;

DROP ROLE IF EXISTS adviser;

\list \dn