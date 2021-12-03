package main

import (
	"github.com/solo-io/go-utils/githubutils"
)

func main() {
	const buildDir = "_output"
	const repoOwner = "solo-io"
	const repoName = "bumblebee"

	assets := []githubutils.ReleaseAssetSpec{
		{
			Name:       "bee-linux-amd64",
			ParentPath: buildDir,
			UploadSHA:  true,
		},
		{
			Name:       "bee-linux-arm64",
			ParentPath: buildDir,
			UploadSHA:  true,
		},
	}
	spec := githubutils.UploadReleaseAssetSpec{
		Owner:             repoOwner,
		Repo:              repoName,
		Assets:            assets,
		SkipAlreadyExists: true,
	}
	githubutils.UploadReleaseAssetCli(&spec)
}
