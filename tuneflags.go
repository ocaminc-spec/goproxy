// Copyright (c) 2026 Ocam. SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// tuneFlag links an Advanced-tab setting to the command-line flag it overrides.
type tuneFlag struct {
	Key, Flag string
	Min, Max  float64
	Dur       time.Duration // flag is a duration in this unit (0 = plain number / bool)
	Bool      bool
	get       func(t *TuneOverrides) any
}

var tuneFlags = []tuneFlag{
	{Key: "cache_gb", Flag: "cache-gb", Min: 4, Max: 64, get: func(t *TuneOverrides) any { return t.CacheGB }},
	{Key: "cache_mb", Flag: "cache-mb", Min: 64, Max: 65536, get: func(t *TuneOverrides) any { return t.CacheMB }},
	{Key: "min_ttl_sec", Flag: "min-ttl", Min: 0, Max: 3600, Dur: time.Second, get: func(t *TuneOverrides) any { return t.MinTTLSec }},
	{Key: "max_ttl_sec", Flag: "max-ttl", Min: 60, Max: 7 * 86400, Dur: time.Second, get: func(t *TuneOverrides) any { return t.MaxTTLSec }},
	{Key: "stale_sec", Flag: "stale", Min: 0, Max: 86400, Dur: time.Second, get: func(t *TuneOverrides) any { return t.StaleSec }},
	{Key: "stale_timeout_ms", Flag: "stale-timeout", Min: 0, Max: 10000, Dur: time.Millisecond, get: func(t *TuneOverrides) any { return t.StaleTimeoutMs }},
	{Key: "prefetch_hits", Flag: "prefetch-hits", Min: 1, Max: 1000, get: func(t *TuneOverrides) any { return t.PrefetchHits }},
	{Key: "prefetch_at", Flag: "prefetch-at", Min: 0, Max: 1, get: func(t *TuneOverrides) any { return t.PrefetchAt }},
	{Key: "siblings", Flag: "prefetch-siblings", Bool: true, get: func(t *TuneOverrides) any { return t.Siblings }},
	{Key: "keep_hot", Flag: "keep-hot", Min: 0, Max: 5000, get: func(t *TuneOverrides) any { return t.KeepHot }},
	{Key: "warmup", Flag: "warmup", Min: 0, Max: 10000, get: func(t *TuneOverrides) any { return t.Warmup }},
	{Key: "parallel_all", Flag: "parallel-all", Bool: true, get: func(t *TuneOverrides) any { return t.ParallelAll }},
	{Key: "plain_fallback", Flag: "plain-fallback", Bool: true, get: func(t *TuneOverrides) any { return t.PlainFallback }},
	{Key: "warmup_rate", Flag: "warmup-rate", Min: 0, Max: 5000, get: func(t *TuneOverrides) any { return t.WarmupRate }},
	{Key: "race_first", Flag: "race-first", Min: 1, Max: 8, get: func(t *TuneOverrides) any { return t.RaceFirst }},
}

// value returns the override as a flag string, or "" when unset.
func (tf tuneFlag) value(t *TuneOverrides) (string, float64, bool) {
	switch v := tf.get(t).(type) {
	case *int64:
		if v == nil {
			return "", 0, false
		}
		if tf.Dur > 0 {
			return (time.Duration(*v) * tf.Dur).String(), float64(*v), true
		}
		return strconv.FormatInt(*v, 10), float64(*v), true
	case *float64:
		if v == nil {
			return "", 0, false
		}
		return strconv.FormatFloat(*v, 'f', -1, 64), *v, true
	case *bool:
		if v == nil {
			return "", 0, false
		}
		return strconv.FormatBool(*v), 0, true
	}
	return "", 0, false
}

func validateTune(t *TuneOverrides) error {
	for _, tf := range tuneFlags {
		_, n, ok := tf.value(t)
		if !ok || tf.Bool {
			continue
		}
		if n < tf.Min || n > tf.Max {
			return fmt.Errorf("%s must be between %v and %v", tf.Key, tf.Min, tf.Max)
		}
	}
	if t.MinTTLSec != nil && t.MaxTTLSec != nil && *t.MinTTLSec > *t.MaxTTLSec {
		return fmt.Errorf("min_ttl_sec must not be above max_ttl_sec")
	}
	return nil
}

// setFlags records which flags were given explicitly on the command line (they win over
// the Advanced tab).
func setFlags() map[string]bool {
	m := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { m[f.Name] = true })
	return m
}

// applyTuneOverrides sets flags from the saved settings before the engine is built.
func applyTuneOverrides(st Settings, explicit map[string]bool) []string {
	var applied []string
	for _, tf := range tuneFlags {
		v, _, ok := tf.value(&st.Tune)
		if !ok || explicit[tf.Flag] {
			continue
		}
		if err := flag.Set(tf.Flag, v); err == nil {
			applied = append(applied, tf.Flag+"="+v)
		}
	}
	return applied
}

// upstreamList applies the Quad9-ECS choice and the optional extra upstream.
func upstreamList(flagVal string, st Settings, explicit bool) []string {
	list := splitList(flagVal)
	if !explicit && strings.TrimSpace(st.UpstreamSet) != "" {
		list = splitList(st.UpstreamSet)
	}
	if !explicit && st.Quad9ECS {
		var out []string
		added := false
		for _, u := range list {
			if strings.Contains(u, "9.9.9.9") || strings.Contains(u, "149.112.112.112") || strings.Contains(u, "quad9.net") {
				if !added {
					out = append(out, quad9ECS)
					added = true
				}
				continue
			}
			out = append(out, u)
		}
		if !added {
			out = append(out, quad9ECS)
		}
		list = out
	}
	if e := strings.TrimSpace(st.ExtraUpstream); e != "" {
		list = append(list, e)
	}
	return list
}
