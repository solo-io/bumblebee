package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/solo-io/skv2/codegen"
	"github.com/solo-io/skv2/codegen/model"
	"github.com/solo-io/skv2/codegen/render"
	"github.com/solo-io/skv2/codegen/skv2_anyvendor"
	"github.com/solo-io/skv2/codegen/util"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

//go:generate go run generate.go

var (
	// the root directory of the project
	// relative to $PWD
	ProjectRoot = func() string {
		wd, err := os.Getwd()
		if err != nil {
			panic(err)
		}

		fmt.Println(wd)
		rel, err := filepath.Rel(wd, util.GetModuleRoot())
		if err != nil {
			panic(err)
		}
		fmt.Println(rel)
		return rel
	}()
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {

	cmd := codegen.Command{
		AppName: "bumblebee",
		AnyVendorConfig: skv2_anyvendor.CreateDefaultMatchOptions(
			[]string{
				"api/**/*.proto",
			},
		),
		ManifestRoot: filepath.Join(ProjectRoot, "install/helm/bumblebee"),
		Groups: []render.Group{
			{
				Resources: []render.Resource{
					{
						Kind: "Probe",
						Spec: render.Field{
							Type: model.Type{
								Name: "ProbeSpec",
							},
						},
						ShortNames: []string{"pr"},
						Categories: []string{"solo-io", "bumbebee"},
					},
				},
				RenderFieldJsonDeepcopy: true,
				Module:                  "github.com/solo-io/bumblebee",
				ApiRoot:                 "pkg/api",
				GroupVersion: schema.GroupVersion{
					Group:   "probes.bumblebee.io",
					Version: "v1alpha1",
				},
				RenderManifests: true,
				// AddChartVersion:         GetLatestVersion(),
				RenderValidationSchemas: true,
				RenderTypes:             true,
				RenderClients:           true,
				RenderController:        true,
				MockgenDirective:        true,
			},
		},
		RenderProtos: true,
		// Chart:        ,
	}

	return cmd.Execute()
}

// func genApis() codegen.Command {
// 	return codegen.Command{
// 		AppName:         "bumblebee-apis",
// 		AnyVendorConfig: anyvendor.Imports(),
// 		ManifestRoot:    filepath.Join(ProjectRoot, charts.CrdsChartPath),
// 		Groups:          allBumblebeeGroups,
// 		RenderProtos:    true,
// 		Chart:           charts.CrdsChart,
// 	}
// }

// func genBumblbeeChart() codegen.Command {
// 	return codegen.Command{
// 		AppName:      "gloo-mesh-enterprise",
// 		ManifestRoot: filepath.Join(ProjectRoot, "install/helm/gloo-mesh-enterprise"),
// 		Chart:        charts.GlooMeshEnterpriseChart,
// 	}
// }

// var (
// 	loadLatestVersion = &sync.Once{}

// 	latestVersion string
// )

// func GetLatestVersion() string {
// 	// Only search for the latest version once
// 	loadLatestVersion.Do(func() {
// 		var err error
// 		root := util.GetModuleRoot()
// 		latestVersion, err = GetLatestVersionFromChangelogDir(os.DirFS(root))
// 		if err != nil {
// 			log.Fatal(err)
// 		}
// 	})
// 	return latestVersion
// }

// func GetLatestVersionFromChangelogDir(fsys fs.FS) (string, error) {
// 	// Get all entries from the changelog directory
// 	dirEntry, err := fs.ReadDir(fsys, changelogutils.ChangelogDirectory)
// 	if err != nil {
// 		return "", err
// 	}
// 	var versions []versionutils.Version
// 	for _, v := range dirEntry {
// 		// We only care about directories
// 		if !v.IsDir() {
// 			continue
// 		}
// 		// Parse all of our versions so we can sort them later
// 		parsed, err := versionutils.ParseVersion(v.Name())
// 		if err != nil {
// 			return "", err
// 		}
// 		versions = append(versions, *parsed)
// 	}
// 	changelogdocutils.SortReleaseVersions(versions)
// 	// After sorting grab the newest version
// 	return versions[0].String(), nil
// }
