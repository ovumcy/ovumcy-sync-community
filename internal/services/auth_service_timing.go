package services

import "golang.org/x/crypto/bcrypt"

// passwordTimingEqualizationHash is a fixed bcrypt cost-10 placeholder used
// by equalizePasswordTiming to spend bcrypt compute on the early-return
// branches of login and forgot-password. It is never compared against a real
// credential — the bcrypt result is always discarded — and never
// authenticates anyone. Its only role is timing parity so an attacker cannot
// distinguish "no such account" or "account exists with no recovery code
// set" from "wrong credential" by measuring response latency.
const passwordTimingEqualizationHash = "$2a$10$Q7IZRfDUMDOhB6kCZh/PUu6NoRiEXQXqr6PE9hFw9Xnb2CN5ESQHC" // #nosec G101 -- fixed placeholder bcrypt hash, never authenticates a real user

// equalizePasswordTiming is a package-level variable so tests can substitute
// a counting stub. The default implementation runs a real bcrypt comparison
// against passwordTimingEqualizationHash; tests that want to assert the
// equalizer was actually invoked replace this with a counting function and
// avoid wall-clock fragility.
var equalizePasswordTiming = func(plain string) {
	_ = bcrypt.CompareHashAndPassword([]byte(passwordTimingEqualizationHash), []byte(plain))
}
