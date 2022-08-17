package transverse

import (
	"log"
	"os"
)

var (
	logger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Lmicroseconds|log.Lshortfile)
	error  = log.New(os.Stdout, "ERROR: ", log.Ldate|log.Lmicroseconds|log.Lshortfile)
)

func Logger() *log.Logger {
	return logger
}

func LoggerError() *log.Logger {
	return error
}

func LogDnssec(format string, params ...interface{}) {
	if FlagLogDnssec {
		Logger().Printf(format, params...)
	}
}
