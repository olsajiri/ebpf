package link

import (
	"testing"

	"github.com/go-quicktest/qt"
)

type usdtTarget struct {
	provider string
	name     string
}

func TestUsdtTargets(t *testing.T) {
	ex, err := OpenExecutable("/home/jolsa/ebpf/usdt")
	qt.Assert(t, qt.IsNil(err))

	targets, err := ex.UsdtTargets()
	qt.Assert(t, qt.IsNil(err))

	checks := [3]usdtTarget{
		{provider: "test", name: "usdt0"},
		{provider: "test", name: "usdt3"},
		{provider: "test", name: "usdt12"},
	}

	found := 0
	for _, target := range targets {
		for _, chk := range checks {
			if chk.provider == target.Spec.Provider && chk.name == target.Spec.Name {
				found++
			}
		}
	}
	qt.Assert(t, qt.Equals(found, 3))
}
