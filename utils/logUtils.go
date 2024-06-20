package utils

import (
	"fmt"
	"log"
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

	year := dt.Year()
	month := dt.Month()
	day := dt.Day()
	hour := dt.Hour()
	minute := dt.Minute()
	second := dt.Second()
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, second)
}

func LogInfo(msg string) {
	fmt.Printf("[%s - %s] %s\n", INFO, currentHourMinuteSecond(), msg)
}

func LogFatal(msg string) {
	log.Fatalf("[%s - %s] %s\n", FATAL, currentHourMinuteSecond(), msg)
}
