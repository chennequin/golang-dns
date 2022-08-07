package transverse

const (
	defaultRetryCount = 2
)

var (
	LogDnssec     = false
	LogHttpsCerts = true
	EnableTrace   = true

	pathToCertificates = "./"
	retry              = defaultRetryCount
)

func GetPath() string {
	return pathToCertificates
}

func GetRetry() int {
	return retry
}

func SetTest() {
	LogHttpsCerts = false
	EnableTrace = false
	LogDnssec = false
	pathToCertificates = "../../"
	retry = 0
}
