\set ON_ERROR_STOP on

-- Database: adviserdb


SELECT
    EXISTS(SELECT datname  FROM pg_catalog.pg_database WHERE datname = 'adviserdb') as adviserdb_exists \gset

\if :adviserdb_exists
\echo 'adviserdb already exists!'
\c adviserdb
\dt
\q
\endif

-- template0: see https://blog.dbi-services.com/what-the-hell-are-these-template0-and-template1-databases-in-postgresql/
CREATE DATABASE adviserdb
WITH
    OWNER = postgres ENCODING = 'UTF8' LC_COLLATE = 'en_US.UTF-8' LC_CTYPE = 'en_US.UTF-8' TEMPLATE template0 CONNECTION
LIMIT = -1;

CREATE ROLE adviser NOSUPERUSER NOCREATEDB NOCREATEROLE NOLOGIN;

CREATE USER promptviser NOCREATEDB IN GROUP adviser;