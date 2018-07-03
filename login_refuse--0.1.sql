/* contrib/login_refuse/login_refuse--0.1.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION login_refuse" to load this file. \quit

CREATE FUNCTION login_refuse_set_expire_time(text, bigint)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;

CREATE FUNCTION login_refuse_reset_expire_time(text)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C;