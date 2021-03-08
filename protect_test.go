package nativeprotect

import "testing"

func TestProtect(t *testing.T) {
	got, err := Protect(nil)
	if err != nil {
		t.Error(err)
	}
	if got == nil {
		t.Error("Got empty machine id")
	}
}
