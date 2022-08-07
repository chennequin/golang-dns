package transverse

import (
	"log"
	"os"
)

var (
	logger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
)

func Logger() *log.Logger {
	return logger
}
