package utils

import (
	"fmt"
	"strings"
	"time"
)

func CurrentDateTime(replaceSpace ...bool) string {
	dt := time.Now()

	year, month, day := dt.Date()
	hour, minute, second := dt.Clock()

	val := fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, second)
	if len(replaceSpace) > 0 && replaceSpace[0] {
		return strings.ReplaceAll(val, " ", "_")
	} else {
		return val
	}
}
