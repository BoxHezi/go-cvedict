package services

import (
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func prepareConditionFromId(id string) bson.E {
	return bson.E{Key: "id", Value: id}
}

func prepareConditionFromYear(year string) bson.E {
	return bson.E{Key: "id", Value: primitive.Regex{Pattern: fmt.Sprintf("CVE-%s-", year)}}
}

func prepareConditionFromDesc(desc string) bson.E {
	return bson.E{Key: "descriptions.value", Value: primitive.Regex{Pattern: desc, Options: "i"}}
}
