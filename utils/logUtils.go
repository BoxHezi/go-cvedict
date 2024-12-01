package utils

import (
	"fmt"
	"log"
)

const (
	infoHint    = "INFO"
	warningHint = "WARNING"
	errorHint   = "ERROR"
	debugHint   = "DEBUG"
	fatalHint   = "FATAL"
)

func LogInfo(msg string) {
	fmt.Printf("[%s - %s] %s\n", infoHint, CurrentDateTime(), msg)
}

func LogDebug(msg string) {
	fmt.Printf("[%s - %s] %s\n", debugHint, CurrentDateTime(), msg)
}

func LogError(err error) {
	fmt.Printf("[%s - %s] %s\n", errorHint, CurrentDateTime(), err)
}

func LogFatal(msg error) {
	log.Fatalf("[%s - %s] %s\n", fatalHint, CurrentDateTime(), msg)
}
