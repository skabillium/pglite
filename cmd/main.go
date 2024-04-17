package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
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

func (ng *Engine) executeCreate(stmt *pgquery.CreateStmt) error {
	fmt.Println("Creating table:", stmt.Relation.Relname)
	return nil
}

func (ng *Engine) executeInsert(stmt *pgquery.InsertStmt) error {
	fmt.Println("Executing insert")
	return nil
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

type TableDefinition struct {
	Name        string
	ColumnNames []string
	ColumnTypes []string
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
	var httpPort, raftPort, user, password, dataDir string
	flag.StringVar(&httpPort, "http-port", "6000", "Http port")
	flag.StringVar(&raftPort, "raft-port", "6001", "Raft port")
	flag.StringVar(&user, "user", "pglite", "User")
	flag.StringVar(&password, "password", "password", "Password")
	flag.StringVar(&dataDir, "data-dir", "pglite-data", "Data directory")
	flag.Parse()

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

	http.HandleFunc("POST /follower", func(w http.ResponseWriter, r *http.Request) {
		if hasAuth, err := HasAuth(r.Header.Get("Authorization"), user, password); !hasAuth {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("Follower added"))
	})
	http.HandleFunc("POST /query", func(w http.ResponseWriter, r *http.Request) {
		if hasAuth, err := HasAuth(r.Header.Get("Authorization"), user, password); !hasAuth {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
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

		engine.Execute(query)

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Running query: " + query + "\n"))
	})

	err = http.ListenAndServe(":"+httpPort, nil)
	if err != nil {
		log.Fatal(err)
	}
}
