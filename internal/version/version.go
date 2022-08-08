package version

var DevVersion = "dev"

// This will be set by the linker on release builds
var Version string

func init() {
	if Version == "" {
		Version = DevVersion
	}
}
