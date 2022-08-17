package transverse

const (
	defaultRetryCount = 1
)

var (
	FlagLogDnssec       = false
	FlagLogHttpsCerts   = false
	FlagHttpEnableTrace = false

	retry = defaultRetryCount
)

func GetRetry() int {
	return retry
}

func SetTest() {

	FlagLogHttpsCerts = false
	FlagHttpEnableTrace = false
	FlagLogDnssec = false

	retry = 0
}
