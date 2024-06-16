package server

import (
	"fmt"

	"github.com/gin-gonic/gin"

	model "cve-dict/model"

	dbServices "cve-dict/services"
)

var dbConfig model.DbConfig

func parseRootFlags(rootFlags *model.RootFlag) {
	dbConfig.SetDbHost(*rootFlags.GetAddressP())
	dbConfig.SetDbPort(*rootFlags.GetPortP())
	dbConfig.SetDatabase(*rootFlags.GetDatabaseP())
	dbConfig.SetCollection(*rootFlags.GetCollectionP())
}

func ServerMain(port uint32, rootFlags *model.RootFlag) {
	parseRootFlags(rootFlags)

	router := gin.Default()
	router.GET("/cve/id/:cveid", handleCveid)
	router.GET("/cve/year/:year", handleCveByYear)

	router.Run(fmt.Sprintf(":%d", port))
}

func handleCveid(c *gin.Context) {
	cveid := c.Param("cveid")

	var cves []model.Cve = dbServices.QueryByCveId(dbConfig, cveid)

	c.JSON(200, gin.H{
		"data": cves,
	})
}

func handleCveByYear(c *gin.Context) {
	year := c.Param("year")

	c.JSON(200, gin.H{
		"data": dbServices.QueryByYear(dbConfig, year),
		// "year": year,
	})
}
