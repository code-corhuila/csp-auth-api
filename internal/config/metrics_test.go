package config

import "testing"

func TestLoadEnablesTheMetricsByDefaultAndReadsTheSwitch(t *testing.T) {
	cfg, err := Load(lookupFrom(nil))
	if err != nil || !cfg.MetricsEnabled {
		t.Fatalf("default: enabled = %v, err = %v; want true", cfg.MetricsEnabled, err)
	}
	for value, want := range map[string]bool{"true": true, "false": false, "0": false, "1": true} {
		cfg, err := Load(lookupFrom(map[string]string{"APP_AUTH_METRICS_ENABLED": value}))
		if err != nil || cfg.MetricsEnabled != want {
			t.Errorf("APP_AUTH_METRICS_ENABLED=%s: enabled = %v, err = %v; want %v", value, cfg.MetricsEnabled, err, want)
		}
	}
}

func TestLoadRejectsAnInvalidMetricsSwitch(t *testing.T) {
	for _, value := range []string{"yes please", "enabled", "2"} {
		if _, err := Load(lookupFrom(map[string]string{"APP_AUTH_METRICS_ENABLED": value})); err == nil {
			t.Errorf("APP_AUTH_METRICS_ENABLED=%s: Load() error = nil", value)
		}
	}
}
