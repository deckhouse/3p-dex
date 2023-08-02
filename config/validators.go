package config

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/xeipuuv/gojsonschema"
)

type durationFormatChecker struct{}

func (f durationFormatChecker) IsFormat(input interface{}) bool {
	duration, ok := input.(string)
	if !ok {
		return false
	}

	_, err := time.ParseDuration(duration)
	return err == nil
}

type listenAddressFormatChecker struct{}

func (f listenAddressFormatChecker) IsFormat(input interface{}) bool {
	hostport, ok := input.(string)
	if !ok {
		return false
	}

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return false
	}

	if _, err := strconv.Atoi(port); err != nil {
		return false
	}

	if ip := net.ParseIP(host); ip == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		res, err := net.DefaultResolver.LookupAddr(ctx, host)
		if err != nil {
			return false
		}

		if len(res) > 0 {
			return false
		}
	}

	return true
}

func init() {
	gojsonschema.FormatCheckers.Add("duration", durationFormatChecker{})
	gojsonschema.FormatCheckers.Add("listen-address", listenAddressFormatChecker{})
}
