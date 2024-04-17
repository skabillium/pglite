package main

import (
	"log"

	"github.com/auxten/postgresql-parser/pkg/sql/parser"
	"github.com/auxten/postgresql-parser/pkg/walk"
)

func main() {
	q := "SELECT name, email FROM user"

	stmts, err := parser.Parse(q)
	if err != nil {
		panic(err)
	}

	w := &walk.AstWalker{
		Fn: func(ctx any, node any) (stop bool) {
			log.Printf("node type %T", node)
			return false
		},
	}

	w.Walk(stmts, nil)
}
