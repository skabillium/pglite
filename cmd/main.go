package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v5"
	bolt "go.etcd.io/bbolt"
)

// Storage engine implementation using "bbolt". This structure is responsible for
// providing the necessary primitives for reading entities like tables and rows.
type Engine struct {
	db         *bolt.DB
	bucketName []byte
}

func NewEngine(db *bolt.DB) *Engine {
	return &Engine{db, []byte("data")}
}

// Fetch a table definition by name
func (ng *Engine) getTable(name string) *TableDefinition {
	key := "tables:" + name
	var tableDef *TableDefinition
	ng.db.View(func(tx *bolt.Tx) error {
		buck := tx.Bucket(ng.bucketName)
		if buck == nil {
			return nil
		}
		tb := buck.Get([]byte(key))
		tableDef = DecodeTableDef(tb)
		return nil
	})
	return tableDef
}

// Write a table definitio to disk
func (ng *Engine) writeTable(table TableDefinition) error {
	key := []byte("tables:" + table.Name)
	return ng.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket(ng.bucketName)
		return buck.Put(key, table.Encode())

	})
}

// Get a table's rows
func (ng *Engine) getAllRows(table *TableDefinition, fields []string) ([][]any, error) {
	var results [][]any
	err := ng.db.View(func(tx *bolt.Tx) error {
		prefix := []byte("row:" + table.Name + ":")
		cursor := tx.Bucket(ng.bucketName).Cursor()
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			var row []any
			err := json.Unmarshal(v, &row)
			if err != nil {
				return fmt.Errorf("unable to unmarshal row: %s", err)
			}

			var selected []any
			for _, field := range fields {
				selected = append(selected, row[slices.Index(table.ColumnNames, field)])
			}
			results = append(results, selected)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return results, nil
}

// Write a row to disk
func (ng *Engine) writeRow(table *TableDefinition, row []any) error {
	id := row[0].(string)
	key := []byte("row:" + table.Name + ":" + id)

	rowb, err := json.Marshal(row)
	if err != nil {
		return errors.New("error while encoding row")
	}

	return ng.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket(ng.bucketName)
		return buck.Put(key, rowb)
	})
}

// Delete all rows from a table
func (ng *Engine) deleteAllRows(table *TableDefinition) (int, error) {
	var deleted int
	err := ng.db.Update(func(tx *bolt.Tx) error {
		prefix := []byte("row:" + table.Name + ":")
		cursor := tx.Bucket(ng.bucketName).Cursor()
		for k, _ := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = cursor.Next() {
			cursor.Delete()
			deleted++
		}
		return nil
	})
	return deleted, err
}

// Delete a single row by id
func (ng *Engine) deleteRowById(table *TableDefinition, id string) error {
	return ng.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket(ng.bucketName)
		key := []byte("row:" + table.Name + ":" + id)
		return buck.Delete(key)
	})
}

// Execute a "CREATE TABLE" statement
func (ng *Engine) executeCreate(stmt *pgquery.CreateStmt) error {
	table := TableDefinition{
		Name:        stmt.Relation.Relname,
		ColumnNames: []string{"id"},
		ColumnTypes: []string{"pg_calalog.varchar"},
	}
	exists := ng.getTable(table.Name)
	if exists != nil {
		return fmt.Errorf("table '%s' already exists", table.Name)
	}

	for _, c := range stmt.TableElts {
		coldef := c.GetColumnDef()
		if coldef.Colname == "id" {
			continue
		}
		table.ColumnNames = append(table.ColumnNames, coldef.Colname)

		var columnType string
		for _, n := range coldef.TypeName.Names {
			if columnType != "" {
				columnType += "."
			}
			columnType += n.GetString_().Sval
		}
		table.ColumnTypes = append(table.ColumnTypes, columnType)
	}

	err := ng.writeTable(table)
	if err != nil {
		return err
	}

	return nil
}

// Contains all information returned by a "SELECT" query
type SelectResult struct {
	Fields []string `json:"fieldNames"`
	Types  []string `json:"fieldTypes"`
	Rows   [][]any  `json:"rows"`
}

// Executes a "SELECT" statement
func (ng *Engine) executeSelect(stmt *pgquery.SelectStmt) (*SelectResult, error) {
	tablename := stmt.FromClause[0].GetRangeVar().Relname
	table := ng.getTable(tablename)
	if table == nil {
		return nil, fmt.Errorf("relation '%s' does not exist", tablename)
	}

	var fieldNames []string
	for _, t := range stmt.TargetList {
		field := t.GetResTarget().Val.GetColumnRef().Fields[0]
		if field.GetAStar() != nil {
			fieldNames = table.ColumnNames
			break
		}

		fieldName := field.GetString_().Sval
		fieldNames = append(fieldNames, fieldName)
	}

	var fieldTypes []string
	for _, f := range fieldNames {
		idx := slices.Index(table.ColumnNames, f)
		if idx == -1 {
			return nil, fmt.Errorf("column '%s' does not exist on table '%s'", f, table.Name)
		}
		fieldTypes = append(fieldTypes, table.ColumnTypes[idx])
	}

	rows, err := ng.getAllRows(table, fieldNames)
	if err != nil {
		return nil, err
	}

	return &SelectResult{Fields: fieldNames, Types: fieldTypes, Rows: rows}, nil
}

// Executes and "INSERT" statement
func (ng *Engine) executeInsert(stmt *pgquery.InsertStmt) error {
	table := ng.getTable(stmt.Relation.Relname)
	if table == nil {
		return fmt.Errorf("table '%s' does not exist", stmt.Relation.Relname)
	}

	sel := stmt.GetSelectStmt().GetSelectStmt()
	row := []any{generateId()}
	for _, values := range sel.ValuesLists {
		for _, value := range values.GetList().Items {
			if f := value.GetColumnRef(); f != nil {
				for _, str := range f.Fields {
					if s := str.GetString_(); s != nil {
						row = append(row, s.Sval)
					}
				}
				continue
			}

			if c := value.GetAConst(); c != nil {
				if s := c.GetSval(); s != nil {
					row = append(row, s.Sval)
					continue
				}
				if i := c.GetIval(); i != nil {
					row = append(row, i.Ival)
					continue
				}
				if b := c.GetBoolval(); b != nil {
					row = append(row, b.Boolval)
					continue
				}
			}

			return fmt.Errorf("unknown value type '%s'", value)
		}
	}

	if len(table.ColumnNames) != len(row) {
		return errors.New("invalid number of values")
	}

	return ng.writeRow(table, row)
}

// Result containing number of deleted rows
type DeleteResult struct {
	Count int `json:"count"`
}

// Executes a "DELETE" statement
func (ng *Engine) executeDelete(stmt *pgquery.DeleteStmt) (int, error) {
	tablename := stmt.Relation.Relname
	table := ng.getTable(tablename)
	if table == nil {
		return -1, fmt.Errorf("relation '%s' does not exist", tablename)
	}

	// Only support deleting by id
	if stmt.WhereClause == nil {
		return ng.deleteAllRows(table)
	}

	where := stmt.WhereClause.GetAExpr()
	if where == nil {
		return -1, errors.New("only deletion by id is supported")
	}

	if where.Lexpr.GetColumnRef().Fields[0].GetString_().Sval != "id" || where.Name[0].GetString_().Sval != "=" {
		return -1, errors.New("only deletion by id is supported")
	}

	aconst := where.Rexpr.GetAConst()
	if aconst == nil {
		return -1, errors.New("id should be a string")
	}

	return 1, ng.deleteRowById(table, aconst.GetSval().Sval)
}

// Parses an SQL query from a string and calls the correct function for the specified statement
// Only "CREATE TABLE", "INSERT", "SELECT" & "DELETE" statements are supported
func (ng *Engine) Execute(query string) (any, error) {
	res, err := pgquery.Parse(query)
	if err != nil {
		return nil, err
	}

	// Only support single statements
	stmt := res.Stmts[0].GetStmt()
	if stmt := stmt.GetCreateStmt(); stmt != nil {
		return nil, ng.executeCreate(stmt)
	}

	if stmt := stmt.GetSelectStmt(); stmt != nil {
		return ng.executeSelect(stmt)
	}

	if stmt := stmt.GetInsertStmt(); stmt != nil {
		return nil, ng.executeInsert(stmt)
	}

	if stmt := stmt.GetDeleteStmt(); stmt != nil {
		count, err := ng.executeDelete(stmt)
		if err != nil {
			return nil, err
		}
		return DeleteResult{Count: count}, nil
	}

	return nil, errors.New("statement not supported")
}

// Create bucket for database storage
func (ng *Engine) Setup() error {
	return ng.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(ng.bucketName)
		return err
	})
}

// Stores all information required for a table definition. This includes
// names and types for every defined column
type TableDefinition struct {
	Name        string
	ColumnNames []string
	ColumnTypes []string
}

// Encode a table definition as json
func (td *TableDefinition) Encode() []byte {
	b, err := json.Marshal(*td)
	if err != nil {
		return nil
	}
	return b
}

// Decode a table definition from json
func DecodeTableDef(b []byte) *TableDefinition {
	var def TableDefinition
	err := json.Unmarshal(b, &def)
	if err != nil {
		return nil
	}
	return &def
}

type PostQueryRequest struct {
	Query string `json:"query"`
}

// Check if the "Authorization" header contains basic user password auth
func HasAuth(authHeader string, user string, pwd string) (bool, error) {
	if authHeader == "" {
		return false, errors.New("empty authorization header")
	}

	if !strings.HasPrefix(authHeader, "Basic ") {
		return false, errors.New("invalid Authorization header")
	}

	base64Credentials := authHeader[len("Basic "):]
	credentials, err := base64.StdEncoding.DecodeString(base64Credentials)
	if err != nil {
		return false, errors.New("failed to decode credentials")
	}

	// Split the credentials into username and password
	parts := strings.SplitN(string(credentials), ":", 2)
	if len(parts) != 2 {
		return false, errors.New("invalid credentials format")
	}

	// Extract the username and password
	username := parts[0]
	password := parts[1]
	if username != user || password != pwd {
		return false, errors.New("invalid credentials")
	}

	return true, nil
}

func main() {
	var (
		httpPort, user, password, dataDir string
		authDisabled                      bool
	)

	flag.StringVar(&httpPort, "http-port", "6000", "Http port")
	flag.StringVar(&user, "user", "pglite", "User")
	flag.StringVar(&password, "password", "password", "Password")
	flag.StringVar(&dataDir, "data-dir", "pglite-data", "Data directory")
	flag.BoolVar(&authDisabled, "noauth", false, "Disable authentication")
	flag.Parse()

	enableAuth := !authDisabled

	if !pathExists(dataDir) {
		log.Println("Creating data dir at", dataDir)
		err := os.Mkdir(dataDir, 0755)
		if err != nil {
			panic(err)
		}
	}

	db, err := bolt.Open(path.Join(dataDir, "pglite.db"), 0600, nil)
	if err != nil {
		log.Fatalf("Could not open bolt db: %s", err)
	}
	defer db.Close()

	engine := NewEngine(db)

	err = engine.Setup()
	if err != nil {
		panic(err)
	}

	http.HandleFunc("POST /query", func(w http.ResponseWriter, r *http.Request) {
		if enableAuth {
			if hasAuth, err := HasAuth(r.Header.Get("Authorization"), user, password); !hasAuth {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

		// Endpoint accepts both text and json bodies
		query := string(body)
		if r.Header.Get("Content-Type") == "application/json" {
			var req PostQueryRequest
			err = json.Unmarshal(body, &req)
			if err != nil {
				http.Error(w, "Failed to parse json from request body", http.StatusBadRequest)
				return
			}
			query = req.Query
		}

		res, err := engine.Execute(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		if res == nil {
			w.Write([]byte("Succesfully executed query: " + query + "\n"))
			return
		}

		b, err := json.Marshal(res)
		if err != nil {
			w.Write([]byte("Could not marshal response \n"))
			return
		}
		w.Write(b)
	})

	err = http.ListenAndServe(":"+httpPort, nil)
	if err != nil {
		log.Fatal(err)
	}
}

// Generate a random id for a table's row
func generateId() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 20)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

// Check if a path (file/dir) exists in the file system
func pathExists(p string) bool {
	_, err := os.Stat(p)
	return !errors.Is(err, os.ErrNotExist)
}
