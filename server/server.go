package server

import (
	"fmt"

	"github.com/gin-gonic/gin"

	services "cvedict/services"
)

var sc *services.ServicesConfig = new(services.ServicesConfig)

func Run(port uint32, servicesConfig *services.ServicesConfig) {
	sc = servicesConfig

	router := gin.Default()
	router.GET("/cve/id/:cveid", handleCveId)    // exact match, i.e. CVE-2020-12345
	router.GET("/cve/year/:year", handleCveYear) // equipvalent to /search?id=CVE-{year}
	router.GET("/update", handleUpdate)
	router.GET("/search", handleSearch) // when query string is provided, case-insensitive

	router.Run(fmt.Sprintf(":%d", port))
}

func handleCveId(c *gin.Context) {
	cveid := c.Param("cveid")
	query := unpackUriVariable(map[string]string{"id": cveid}, true)
	cves := services.QueryCves(*sc, query)

	c.JSON(200, gin.H{
		"data":  cves,
		"count": len(cves),
	})
}

func handleCveYear(c *gin.Context) {
	year := c.Param("year")
	query := unpackUriVariable(map[string]string{"id": fmt.Sprintf("CVE-%s-", year)}, false)
	cves := services.QueryCves(*sc, query)

	c.JSON(200, gin.H{
		"data":  cves,
		"count": len(cves),
	})
}

func handleUpdate(c *gin.Context) {
	addedCves, modifiedCves := services.DoUpdate(*sc)

	go services.DoUpdateDatabase(*sc, addedCves, modifiedCves, nil, nil)

	c.JSON(200, gin.H{
		"addedCvesCount":    len(addedCves),
		"addedCves":         addedCves,
		"modifiedCvesCount": len(modifiedCves),
		"modifiedCves":      modifiedCves,
	})

	// if sc.notifier != nil {
	// 	content := fmt.Sprintf("Update Operation Completed\n%s - Added: %d, Modified: %d", utils.CurrentDateTime(), len(addedCves), len(modifiedCves))
	// 	sc.notifier.SetContent(content)
	// 	sc.notifier.Send()
	// }
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
	cves := services.QueryCves(*sc, query)

	c.JSON(200, gin.H{
		"data":  cves,
		"count": len(cves),
	})
}
