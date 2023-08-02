package config

import "time"

func MustParseDuration(s string) time.Duration {
	res, err := time.ParseDuration(s)
	if err != nil {
		panic(err)
	}

	return res
}
