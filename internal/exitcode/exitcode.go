package exitcode

// Documented CLI exit codes.
const (
	OK           = 0 // policy passed (warnings allowed)
	PolicyFail   = 1 // one or more error-severity findings
	Usage        = 2 // CLI misuse
	PlanError    = 3 // fail-closed parse/validation
	Internal     = 4 // unexpected internal error
)
