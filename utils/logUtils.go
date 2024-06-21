package utils

import (
	"fmt"
	"time"
)

const (
	INFO    = "INFO"
	WARNING = "WARNING"
	ERROR   = "ERROR"
	DEBUG   = "DEBUG"
	FATAL   = "FATAL"
)

func currentHourMinuteSecond() string {
	dt := time.Now()

	year, month, day := dt.Date()
	hour, minute, second := dt.Clock()
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, second)
}

func LogInfo(msg string) {
	fmt.Printf("[%s - %s] %s\n", INFO, currentHourMinuteSecond(), msg)
}

func LogError(err error) {
	fmt.Printf("[%s - %s] %s\n", ERROR, currentHourMinuteSecond(), err)
}

// func LogFatal(msg string) {
// 	log.Fatalf("[%s - %s] %s\n", FATAL, currentHourMinuteSecond(), msg)
// }
