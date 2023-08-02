package featureflags

import (
	"os"
	"strconv"
	"strings"
)

type Flag struct {
	Name string
}

func (f *Flag) Env() string {
	return "DEX_" + strings.ToUpper(f.Name)
}

func (f *Flag) Enabled() bool {
	res, err := strconv.ParseBool(os.Getenv(f.Env()))
	if err != nil {
		return false
	}
	return res
}

func NewFlag(s string) *Flag {
	return &Flag{Name: s}
}
