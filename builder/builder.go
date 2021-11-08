package builder

import _ "embed"

//go:embed build.sh
var buildScript []byte

func GetBuildScript() []byte {
	return buildScript
}
