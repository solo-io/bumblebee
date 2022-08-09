package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/solo-io/bumblebee/internal/version"
	"github.com/solo-io/bumblebee/pkg/operator"
	"github.com/solo-io/skv2/codegen"
	"github.com/solo-io/skv2/codegen/model"
	"github.com/solo-io/skv2/codegen/model/values"
	"github.com/solo-io/skv2/codegen/render"
	"github.com/solo-io/skv2/codegen/skv2_anyvendor"
	"github.com/solo-io/skv2/codegen/util"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
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
						ShortNames: []string{"pr", "probe"},
						Categories: []string{"solo-io", "bumblebee"},
						AdditionalPrinterColumns: []apiextv1.CustomResourceColumnDefinition{
							{
								Name:        "IMAGE",
								Type:        "string",
								JSONPath:    ".spec.image",
								Description: "The image tag of the probe",
							},
							{
								Name:        "NODE SELECTOR",
								Type:        "string",
								JSONPath:    ".spec.nodeSelector",
								Description: "Node selector for the probe",
							},
							{
								Name:     "CREATION TIMESTAMP",
								Type:     "date",
								JSONPath: ".metadata.creationTimestamp",
							},
						},
					},
				},
				RenderFieldJsonDeepcopy: true,
				Module:                  "github.com/solo-io/bumblebee",
				ApiRoot:                 "pkg/api",
				GroupVersion: schema.GroupVersion{
					Group:   "probes.bumblebee.io",
					Version: "v1alpha1",
				},
				RenderManifests:         true,
				RenderValidationSchemas: true,
				RenderTypes:             true,
				RenderClients:           true,
				MockgenDirective:        true,
			},
		},
		RenderProtos: true,
		Chart: &model.Chart{
			Data: model.Data{
				ApiVersion:  "v2",
				Description: "Bumblebee is a tool for collecting and analyzing system metrics.",
				Name:        "bumblebee",
				Version:     version.Version,
				Home:        "github.com/solo-io/bumblebee",
			},
			Operators: []model.Operator{
				{
					Name: "bumblebee",
					Deployment: model.Deployment{

						UseDaemonSet: true,
						Container: model.Container{
							Env: []corev1.EnvVar{
								{
									Name: "NODE_NAME",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "spec.nodeName",
										},
									},
								},
							},
							Image: values.Image{
								Tag:        version.Version,
								Repository: "operator",
								Registry:   "ghcr.io/solo-io/bumblebee",
							},
							SecurityContext: &corev1.SecurityContext{
								RunAsNonRoot: pointer(false),
								Privileged:   pointer(true),
								RunAsUser:    pointer(int64(0)),
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "image-cache",
									MountPath: operator.ImageCache,
								},
							},
							Args: []string{"operator"},
						},
						Volumes: []corev1.Volume{
							{
								Name: "image-cache",
								VolumeSource: corev1.VolumeSource{
									EmptyDir: &corev1.EmptyDirVolumeSource{},
								},
							},
						},
					},
					Service: model.Service{
						Type: "ClusterIP",
						Ports: []model.ServicePort{
							{
								Name:        "stats",
								DefaultPort: 9001,
							},
						},
					},
					Rbac: []rbacv1.PolicyRule{
						{
							Verbs: []string{
								"get",
								"list",
								"watch",
							},
							APIGroups: []string{"probes.bumblebee.io"},
							Resources: []string{
								"probes",
							},
						},
						{
							Verbs: []string{
								"get",
								"list",
								"watch",
							},
							APIGroups: []string{""},
							Resources: []string{
								"nodes",
							},
						},
					},
				},
			},
		},
	}

	return cmd.Execute()
}

func pointer[T any](val T) *T { return &val }
