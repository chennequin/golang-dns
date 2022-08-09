package transverse

const (
	defaultRetryCount = 2
)

var (
	FlagLogDnssec       = false
	FlagLogHttpsCerts   = false
	FlagHttpEnableTrace = false

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

	FlagLogHttpsCerts = false
	FlagHttpEnableTrace = false
	FlagLogDnssec = false

	pathToCertificates = "../../"
	retry = 0
}
