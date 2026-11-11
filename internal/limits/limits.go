// Package limits documents and enforces parser input bounds.
package limits

const (
	// MaxPlanBytes is the maximum size of a plan JSON document read from file or stdin.
	MaxPlanBytes = 10 << 20 // 10 MiB
	// MaxJSONDepth is the maximum nesting depth when walking parsed JSON values.
	MaxJSONDepth = 64
)
