package services

import (
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	model "cvedict/model"
)

func prepareQuery(searchFlag model.SearchFlag) bson.D {
	var query bson.D = bson.D{}
	if *searchFlag.GetIdP() != "" {
		query = append(query, prepareConditionFromId(*searchFlag.GetIdP()))
	}
	if *searchFlag.GetYearP() != "" {
		query = append(query, prepareConditionFromYear(*searchFlag.GetYearP()))
	}
	if *searchFlag.GetDescP() != "" {
		query = append(query, prepareConditionFromDesc(*searchFlag.GetDescP()))
	}
	return query
}

func prepareConditionFromId(id string) bson.E {
	return bson.E{Key: "id", Value: id}
}

func prepareConditionFromYear(year string) bson.E {
	return bson.E{Key: "id", Value: primitive.Regex{Pattern: fmt.Sprintf("CVE-%s-", year)}}
}

func prepareConditionFromDesc(desc string) bson.E {
	return bson.E{Key: "descriptions.value", Value: primitive.Regex{Pattern: desc, Options: "i"}}
}
