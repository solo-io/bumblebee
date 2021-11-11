package spec_test

import (
	"context"
	"io"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/solo-io/gloobpf/pkg/spec"
	"oras.land/oras-go/pkg/content"
)

var (
	tmpDir string
)

var _ = BeforeSuite(func() {
	tmpdir, err := os.MkdirTemp("", "")
	Expect(err).NotTo(HaveOccurred())
	tmpDir = tmpdir
})

var _ = AfterSuite(func() {
	os.Remove(tmpDir)
})

var _ = Describe("hello", func() {
	It("can push", func() {
		fn, err := os.Open("array.o")
		Expect(err).NotTo(HaveOccurred())

		byt, err := io.ReadAll(fn)
		Expect(err).NotTo(HaveOccurred())

		pkg := &spec.EbpfPackage{
			ProgramFileBytes: byt,
			Description:      "some info",
			Authors:          "me",
			EbpfConfig:       spec.EbpfConfig{},
			Platform: &v1.Platform{
				Architecture: "hello",
				OS:           "linux",
				Variant:      "test",
			},
		}

		reg, err := content.NewOCI(tmpDir)
		Expect(err).NotTo(HaveOccurred())

		registry := spec.NewEbpfOCICLient()

		ctx := context.Background()
		err = registry.Push(ctx, "localhost:5000/oras:test9", reg, pkg)
		Expect(err).NotTo(HaveOccurred())

	})

	It("can pull", func() {
		fn, err := os.Open("array.o")
		Expect(err).NotTo(HaveOccurred())

		byt, err := io.ReadAll(fn)
		Expect(err).NotTo(HaveOccurred())

		pkg := &spec.EbpfPackage{
			ProgramFileBytes: byt,
			Description:      "some info",
			Authors:          "me",
			EbpfConfig:       spec.EbpfConfig{},
			Platform: &v1.Platform{
				Architecture: "hello",
				OS:           "linux",
				Variant:      "test",
			},
		}

		reg, err := content.NewOCI(tmpDir)
		Expect(err).NotTo(HaveOccurred())

		registry := spec.NewEbpfOCICLient()

		ctx := context.Background()
		newPkg, err := registry.Pull(ctx, "localhost:5000/oras:test9", reg)
		Expect(err).NotTo(HaveOccurred())

		Expect(newPkg.Platform).To(Equal(pkg.Platform))
	})
})
