package zkbudget

import "github.com/consensys/gnark/logger"

func init() {
	// gnark's compile/prove/verify logger defaults to process stdout and has no
	// per-operation option. Disable it once before application goroutines start;
	// changing it around each call would race with other gnark operations.
	// Applications may explicitly opt in using gnark/logger.Set during startup,
	// before concurrent use. This setting affects all gnark users in the process.
	logger.Disable()
}
