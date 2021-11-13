package main

import (
	"github.com/solo-io/go-utils/githubutils"
)

func main() {
	const buildDir = "_output"
	const repoOwner = "solo-io"
	const repoName = "ebpf"

	assets := make([]githubutils.ReleaseAssetSpec, 3)
	assets[0] = githubutils.ReleaseAssetSpec{
		Name:       "ebpfctl-linux-amd64",
		ParentPath: buildDir,
		UploadSHA:  true,
	}
	assets[1] = githubutils.ReleaseAssetSpec{
		Name:       "ebpfctl-linux-arm64",
		ParentPath: buildDir,
		UploadSHA:  true,
	}

	spec := githubutils.UploadReleaseAssetSpec{
		Owner:             repoOwner,
		Repo:              repoName,
		Assets:            assets,
		SkipAlreadyExists: true,
	}
	githubutils.UploadReleaseAssetCli(&spec)
}
