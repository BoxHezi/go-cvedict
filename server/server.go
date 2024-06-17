package server

import (
	"fmt"

	"github.com/gin-gonic/gin"

	model "cve-dict/model"

	services "cve-dict/services"
)

var dbConfig *model.DbConfig = new(model.DbConfig) // global database configuration

func Run(port uint32, dbConf *model.DbConfig) {
	dbConfig = dbConf
	// fmt.Printf("%p\n", dbConfig)
	// fmt.Println(dbConfig.DbHost)
	// fmt.Println(dbConfig.DbPort)
	// fmt.Println(dbConfig.Database)
	// fmt.Println(dbConfig.Collection)

	router := gin.Default()
	router.GET("/cve/id/:cveid", handleCveid)
	router.GET("/cve/year/:year", handleCveByYear)
	router.GET("/update", handleUpdate)

	router.Run(fmt.Sprintf(":%d", port))
}

func handleCveid(c *gin.Context) {
	cveid := c.Param("cveid")

	c.JSON(200, gin.H{
		"data": services.QueryByCveId(*dbConfig, cveid),
	})
}

func handleCveByYear(c *gin.Context) {
	year := c.Param("year")

	c.JSON(200, gin.H{
		"data": services.QueryByYear(*dbConfig, year),
	})
}

func handleUpdate(c *gin.Context) {
	var nvdStatus *model.NvdStatus = new(model.NvdStatus)
	nvdStatus.LoadNvdStatus("./nvdStatus.json")

	addedCves, modefiedCves := services.DoUpdate(nvdStatus)
	go services.DoUpdateDatabase(*dbConfig, addedCves, modefiedCves, nil)
	go nvdStatus.SaveNvdStatus("./nvdStatus.json")

	c.JSON(200, gin.H{
		"number of added cves":    len(addedCves),
		"addedCves":               addedCves,
		"number of modified cves": len(modefiedCves),
		"modifiedCves":            modefiedCves,
	})
}
