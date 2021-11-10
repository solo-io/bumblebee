package packaging_test

import (
	"context"
	"io"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/solo-io/gloobpf/pkg/packaging"
	"oras.land/oras-go/pkg/content"
)

var _ = Describe("hello", func() {
	It("can push", func() {
		fn, err := os.Open("array.o")
		Expect(err).NotTo(HaveOccurred())

		byt, err := io.ReadAll(fn)
		Expect(err).NotTo(HaveOccurred())

		pkg := &packaging.EbpfPackage{
			ProgramFileBytes: byt,
			Description:      "some info",
			Author:           "me",
		}

		reg, err := content.NewRegistry(content.RegistryOptions{
			Insecure:  true,
			PlainHTTP: true,
		})
		Expect(err).NotTo(HaveOccurred())

		registry := packaging.NewEbpfRegistry(reg)

		ctx := context.Background()
		err = registry.Push(ctx, "localhost:5000/oras:test6", pkg)
		Expect(err).NotTo(HaveOccurred())

	})

	It("can pull", func() {
		fn, err := os.Open("array.o")
		Expect(err).NotTo(HaveOccurred())

		byt, err := io.ReadAll(fn)
		Expect(err).NotTo(HaveOccurred())

		pkg := &packaging.EbpfPackage{
			ProgramFileBytes: byt,
			Description:      "some info",
			Author:           "me",
		}

		reg, err := content.NewRegistry(content.RegistryOptions{
			Insecure:  true,
			PlainHTTP: true,
		})
		Expect(err).NotTo(HaveOccurred())

		registry := packaging.NewEbpfRegistry(reg)

		ctx := context.Background()
		newPkg, err := registry.Pull(ctx, "localhost:5000/oras:test6")
		Expect(err).NotTo(HaveOccurred())

		Expect(newPkg.Description).To(Equal(pkg.Description))
	})
})
