# PGLite

PGLite is a single-file, SQL database made for educational purposes, it supports a very small subset of the PostgreSQL syntax
and uses [bbolt](https://github.com/etcd-io/bbolt) for the implementation of the storage engine. PGLite has the following
characteristics:

- Supports basic user-password authentication
- Executes queries from HTTP requests to `POST /query`

Only the following queries are supported:
- `CREATE TABLE`
- `SELECT * | [...columns] FROM [table] WHERE id = [id]`, only select by id is supported
- `DELETE FROM [table] [WHERE id = [id]]`, delete all or by id
- `INSERT INTO [table] VALUES ()`, inserts

## Setup

Install the project with `make install` and run `make build`. This will output the executable in `./bin/pglite`, you can take a look
at the available command-line options with `./pglite --help`.

If for example you want to run the server without any authentication run `pglite --noauth`
