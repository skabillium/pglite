package main

import (
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
	"strings"

	pgquery "github.com/pganalyze/pg_query_go/v5"
	bolt "go.etcd.io/bbolt"
)

type Engine struct {
	db         *bolt.DB
	bucketName []byte
}

func NewEngine(db *bolt.DB) *Engine {
	return &Engine{db, []byte("data")}
}

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

func (ng *Engine) writeTable(table TableDefinition) error {
	key := []byte("tables:" + table.Name)
	return ng.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket(ng.bucketName)
		return buck.Put(key, table.Encode())

	})
}

func (ng *Engine) writeRow(table *TableDefinition, row []any) error {
	id := generateId()
	key := []byte("row:" + table.Name + ":" + id)

	// Encode
	rowb, err := json.Marshal(row)
	if err != nil {
		return errors.New("error while encoding row")
	}

	return ng.db.Update(func(tx *bolt.Tx) error {
		buck := tx.Bucket(ng.bucketName)
		return buck.Put(key, rowb)
	})
}

func (ng *Engine) executeCreate(stmt *pgquery.CreateStmt) error {
	table := TableDefinition{Name: stmt.Relation.Relname}
	exists := ng.getTable(table.Name)
	if exists != nil {
		return fmt.Errorf("table '%s' already exists", table.Name)
	}

	for _, c := range stmt.TableElts {
		coldef := c.GetColumnDef()
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

func (ng *Engine) executeInsert(stmt *pgquery.InsertStmt) error {
	table := ng.getTable(stmt.Relation.Relname)
	if table == nil {
		return fmt.Errorf("table '%s' does not exist", stmt.Relation.Relname)
	}

	sel := stmt.GetSelectStmt().GetSelectStmt()
	var row []any
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

func (ng *Engine) executeUpdate(stmt *pgquery.UpdateStmt) error {
	fmt.Println("Executing update")
	return nil
}

func (ng *Engine) executeDelete(stmt *pgquery.DeleteStmt) error {
	fmt.Println("Executing delete")
	return nil
}

func (ng *Engine) Execute(query string) error {
	res, err := pgquery.Parse(query)
	if err != nil {
		return err
	}

	for _, s := range res.Stmts {
		stmt := s.GetStmt()
		if stmt := stmt.GetCreateStmt(); stmt != nil {
			return ng.executeCreate(stmt)
		}

		if stmt := stmt.GetInsertStmt(); stmt != nil {
			return ng.executeInsert(stmt)
		}

		if stmt := stmt.GetUpdateStmt(); stmt != nil {
			return ng.executeUpdate(stmt)
		}

		if stmt := stmt.GetDeleteStmt(); stmt != nil {
			return ng.executeDelete(stmt)
		}

		return errors.New("Statement not supported")
	}

	return nil
}

func (ng *Engine) Setup() error {
	return ng.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(ng.bucketName)
		return err
	})
}

type TableDefinition struct {
	Name        string
	ColumnNames []string
	ColumnTypes []string
}

func (td *TableDefinition) Encode() []byte {
	b, err := json.Marshal(*td)
	if err != nil {
		return nil
	}
	return b
}

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

// Check if a path (file/dir) exists in the file system
func pathExists(p string) bool {
	_, err := os.Stat(p)
	return !errors.Is(err, os.ErrNotExist)
}

func main() {
	var (
		httpPort, raftPort, user, password, dataDir string
		authDisabled                                bool
	)

	flag.StringVar(&httpPort, "http-port", "6000", "Http port")
	flag.StringVar(&raftPort, "raft-port", "6001", "Raft port")
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

	http.HandleFunc("POST /follower", func(w http.ResponseWriter, r *http.Request) {
		if hasAuth, err := HasAuth(r.Header.Get("Authorization"), user, password); !hasAuth {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Follower added"))
	})
	http.HandleFunc("POST /query", func(w http.ResponseWriter, r *http.Request) {
		if enableAuth {
			if hasAuth, err := HasAuth(r.Header.Get("Authorization"), user, password); !hasAuth {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read request body 1", http.StatusBadRequest)
			return
		}
		query := string(body)
		if r.Header.Get("Content-Type") == "application/json" {
			var req PostQueryRequest
			err = json.Unmarshal(body, &req)
			if err != nil {
				http.Error(w, "Failed to read request body 2", http.StatusBadRequest)
				return
			}
			query = req.Query
		}

		err = engine.Execute(query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Running query: " + query + "\n"))
	})

	err = http.ListenAndServe(":"+httpPort, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func generateId() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 20)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
