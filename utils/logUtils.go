package utils

import (
	"fmt"
	"log"
	"time"
)

const (
	infoHint    = "INFO"
	warningHint = "WARNING"
	errorHint   = "ERROR"
	debugHint   = "DEBUG"
	fatalHint   = "FATAL"
)

func currentHourMinuteSecond() string {
	dt := time.Now()

	year, month, day := dt.Date()
	hour, minute, second := dt.Clock()
	return fmt.Sprintf("%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, second)
}

func LogInfo(msg string) {
	fmt.Printf("[%s - %s] %s\n", infoHint, currentHourMinuteSecond(), msg)
}

func LogDebug(msg string) {
	fmt.Printf("[%s - %s] %s\n", debugHint, currentHourMinuteSecond(), msg)
}

func LogError(err error) {
	fmt.Printf("[%s - %s] %s\n", errorHint, currentHourMinuteSecond(), err)
}

func LogFatal(msg error) {
	log.Fatalf("[%s - %s] %s\n", fatalHint, currentHourMinuteSecond(), msg)
}
