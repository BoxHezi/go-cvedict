package server

import (
	"fmt"

	"github.com/gin-gonic/gin"

	model "cvedict/model"
	services "cvedict/services"
	utils "cvedict/utils"
)

var dbConfig *model.DbConfig = new(model.DbConfig) // global database configuration
var notifier *model.Notifier = new(model.Notifier) // global notifier configuration

func Run(port uint32, dbConf *model.DbConfig, n *model.Notifier) {
	dbConfig = dbConf
	notifier = n

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

	addedCves, modifiedCves := services.DoUpdate(nvdStatus)
	go services.DoUpdateDatabase(*dbConfig, addedCves, modifiedCves, nil)
	go nvdStatus.SaveNvdStatus("./nvdStatus.json")

	c.JSON(200, gin.H{
		"addedCvesCount":    len(addedCves),
		"addedCves":         addedCves,
		"modifiedCvesCount": len(modifiedCves),
		"modifiedCves":      modifiedCves,
	})

	if notifier != nil {
		content := fmt.Sprintf("Update Operation Completed\n%s - Added: %d, Modified: %d", utils.CurrentDateTime(), len(addedCves), len(modifiedCves))
		notifier.SetContent(content)
		notifier.Send()
	}
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
