package models

import "testing"

func TestMarshalLabelsStableOrder(t *testing.T) {
	labels := map[string]string{"b": "2", "a": "1"}
	if out := MarshalLabels(labels); out != "{\"a\":\"1\",\"b\":\"2\"}" {
		t.Fatalf("unexpected order: %s", out)
	}
	if out := MarshalLabels(nil); out != "" {
		t.Fatalf("expected empty string")
	}
}
