package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"strings"
)

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

func main() {
	var httpPort, raftPort, user, password string
	flag.StringVar(&httpPort, "http-port", "6000", "Http port")
	flag.StringVar(&raftPort, "raft-port", "6001", "Raft port")
	flag.StringVar(&user, "user", "pglite", "User")
	flag.StringVar(&password, "password", "password", "Password")
	flag.Parse()

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

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Running query: " + query + "\n"))
	})

	err := http.ListenAndServe(":"+httpPort, nil)
	if err != nil {
		log.Fatal(err)
	}
}
