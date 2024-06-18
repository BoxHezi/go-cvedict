package server

import (
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// unpackQueryString generates a BSON query for MongoDB based on a map of key-value pairs.
//
// Parameters:
// - params: a map of key-value pairs where the keys represent the field names and the values represent the field values.
//
// Returns:
// - query: a BSON document representing the query to be used in MongoDB.
func unpackQueryString(params map[string][]string) bson.D {
	var query bson.D
	for k, v := range params {
		query = append(query, bson.E{Key: k, Value: primitive.Regex{Pattern: v[0], Options: "i"}})
	}
	return query
}

// unpackUriVariable generates a BSON query for MongoDB based on a map of key-value pairs.
//
// Parameters:
// - kv: a map of key-value pairs where the keys represent the field names and the values represent the field values.
// - exactMatch: a boolean indicating whether the query should match the field values exactly or use a regular expression.
//
// Returns:
// - query: a BSON query in the form of a bson.D struct.
func unpackUriVariable(params map[string]string, exactMatch bool) bson.D {
	var query bson.D
	for k, v := range params {
		if exactMatch {
			query = append(query, bson.E{Key: k, Value: v})
		} else {
			query = append(query, bson.E{Key: k, Value: primitive.Regex{Pattern: v, Options: "i"}})
		}
	}
	return query
}
