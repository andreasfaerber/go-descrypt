package descrypt

import (
	"testing"
)

// Test vectors from system crypt(3) - verified on 2026-05-27
var testVectors = []struct {
	password string
	salt     string
	expected string
}{
	{"", "..", "..X8NBuQ4l6uQ"},
	{"hello", "Hi", "HiSNjNMqrRIVA"},
	{"hello world", "HZ", "HZ2O4DBYSwQTk"},
	{"abc", "XY", "XYPRL0FZ7S.EY"},
	{"password", "pa", "papAq5PwY/QQM"},
	{"test", "te", "teH0wLIpW0gyQ"},
	{"a", "aa", "aafKPWZb/dLAs"},
	{"short", "SH", "SHDFwEo41Qzgw"},
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
			// DES crypt only uses first 8 characters, so the wrong password
			// must differ within those 8 characters to produce a different hash
			var wrongPassword string
			if len(tc.password) == 0 {
				wrongPassword = "X"
			} else if len(tc.password) < 8 {
				wrongPassword = tc.password + "X"
			} else {
				wrongPassword = tc.password[:7] + "X"
			}
			if Verify(wrongPassword, tc.expected) {
				t.Errorf("Verify(%q, %q) = true, want false", wrongPassword, tc.expected)
			}
		})
	}
}

func TestGenerateSalt(t *testing.T) {
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
