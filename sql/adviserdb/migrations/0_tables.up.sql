BEGIN;

-- this is needed before migration to Postgres 15
ALTER DATABASE adviserdb OWNER to promptviser;

--
--
--
COMMIT;