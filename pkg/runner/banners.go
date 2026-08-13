package runner

import (
	updateutils "github.com/projectdiscovery/utils/update"
)

// Version is the current version of subfaster
const version = `v2.18.0`

// GetUpdateCallback returns a callback function that updates subfaster
func GetUpdateCallback() func() {
	return func() {
		updateutils.GetUpdateToolCallback("subfaster", version)()
	}
}
