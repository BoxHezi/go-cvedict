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
	router.GET("/ping", handlePing)
	router.GET("/cve/:cveid", handleCveid)

	router.Run(fmt.Sprintf(":%d", port))
}

func handlePing(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "pong",
		"test":    "from handlePing",
	})
}

func handleCveid(c *gin.Context) {
	cveid := c.Param("cveid")

	dbServices.QueryByCveId(dbConfig, cveid)

	c.JSON(200, gin.H{
		"cveid": cveid,
	})
}
