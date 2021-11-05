package packaging_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestPackaging(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Packaging Suite")
}
