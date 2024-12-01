package utils

import (
	"fmt"
	"time"
)

func CurrentDateTime() string {
	dt := time.Now()

	year, month, day := dt.Date()
	hour, minute, second := dt.Clock()
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, second)
}
