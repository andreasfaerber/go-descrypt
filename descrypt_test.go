package descrypt

import (
	"testing"
)

// Test vectors from traditional crypt(3) implementations
var testVectors = []struct {
	password string
	salt     string
	expected string
}{
	{"", "..", "..EXN0q..9..M"},
	{"hello", "Hi", "HiT9fJN1A8c.2"},
	{"hello world", "HZ", "HZdYrHqNv9xkA"},
	{"abc", "XY", "XYM8SfFoZ9pT."},
	{"password", "pa", "paFkM4qXy5nE."},
	{"test", "te", "teN9RHBQJBPz6"},
	{"a", "aa", "aaW8bIvMqX9k."},
	{"short", "SH", "SHkL8N9vZx1q."},
}

func TestEncrypt(t *testing.T) {
	for _, tc := range testVectors {
		t.Run(tc.password, func(t *testing.T) {
			hash, err := Encrypt(tc.password, tc.salt)
			if err != nil {
				t.Fatalf("Encrypt(%q, %q) error: %v", tc.password, tc.salt, err)
			}
			if hash != tc.expected {
				t.Errorf("Encrypt(%q, %q) = %q, want %q", tc.password, tc.salt, hash, tc.expected)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	for _, tc := range testVectors {
		t.Run(tc.password, func(t *testing.T) {
			if !Verify(tc.password, tc.expected) {
				t.Errorf("Verify(%q, %q) = false, want true", tc.password, tc.expected)
			}
			if Verify(tc.password+"wrong", tc.expected) {
				t.Errorf("Verify(%q, %q) = true, want false", tc.password+"wrong", tc.expected)
			}
		})
	}
}

func TestGenerateSalt(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		salt, err := GenerateSalt()
		if err != nil {
			t.Fatalf("GenerateSalt() error: %v", err)
		}
		if len(salt) != SaltLen {
			t.Errorf("GenerateSalt() len = %d, want %d", len(salt), SaltLen)
		}
		for _, c := range salt {
			if !isValidIto64(byte(c)) {
				t.Errorf("GenerateSalt() contains invalid char %q", c)
			}
		}
		if seen[salt] {
			t.Errorf("GenerateSalt() produced duplicate: %q", salt)
		}
		seen[salt] = true
	}
}

func TestEncryptInvalidSalt(t *testing.T) {
	_, err := Encrypt("test", "X")
	if err == nil {
		t.Error("Encrypt with short salt should error")
	}

	_, err = Encrypt("test", "!!")
	if err == nil {
		t.Error("Encrypt with invalid salt chars should error")
	}
}

func TestVerifyInvalidHash(t *testing.T) {
	if Verify("test", "short") {
		t.Error("Verify with short hash should return false")
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Encrypt("password", "pa")
	}
}
