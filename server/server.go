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
	router.GET("/cve/id/:cveid", handleCveid)      // exact match, i.e. CVE-2020-12345
	router.GET("/cve/year/:year", handleCveByYear) // equipvalent to /search?id=CVE-{year}
	router.GET("/update", handleUpdate)

	router.GET("/search", handleSearch) // when query string is provided

	router.Run(fmt.Sprintf(":%d", port))
}

func handleCveid(c *gin.Context) {
	cveid := c.Param("cveid")
	query := unpackUriVariable(map[string]string{"id": cveid}, true)
	cves := services.QueryCves(*dbConfig, query)

	c.JSON(200, gin.H{
		"data":  cves,
		"count": len(cves),
	})
}

func handleCveByYear(c *gin.Context) {
	year := c.Param("year")
	query := unpackUriVariable(map[string]string{"id": fmt.Sprintf("CVE-%s-", year)}, false)
	cves := services.QueryCves(*dbConfig, query)

	c.JSON(200, gin.H{
		"data":  cves,
		"count": len(cves),
	})
}

func handleUpdate(c *gin.Context) {
	nvdStatus := model.InitNvdStatus()

	addedCves, modefiedCves := services.DoUpdate(nvdStatus)
	go services.DoUpdateDatabase(*dbConfig, addedCves, modefiedCves, nil)
	go nvdStatus.SaveNvdStatus("./nvdStatus.json")

	c.JSON(200, gin.H{
		"addedCvesCount":    len(addedCves),
		"addedCves":         addedCves,
		"modifiedCvesCount": len(modefiedCves),
		"modifiedCves":      modefiedCves,
	})
}

func handleSearch(c *gin.Context) {
	if len(c.Request.URL.Query()) == 0 {
		c.JSON(200, gin.H{
			"data":  nil,
			"count": 0,
		})
		return
	}

	query := unpackQueryString(c.Request.URL.Query())
	cves := services.QueryCves(*dbConfig, query)

	c.JSON(200, gin.H{
		"data":  cves,
		"count": len(cves),
	})
}
