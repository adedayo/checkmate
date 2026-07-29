package util

import (
	"log"
	"os"
)

//Log and flush stdout. To be used by plugins, so we can stream plugin output in CheckMate service
func Log(format string, v ...interface{}) {
	log.Printf(format, v...)
	os.Stdout.Sync()
}
