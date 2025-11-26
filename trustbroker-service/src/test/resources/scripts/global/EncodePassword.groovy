// Script outputs first argument encoded with Argon2.
// The output can be used e.g. for encoding OIDC client secrets (OidcClient.clientSecret).
package scripts

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder

var encoder = new Argon2PasswordEncoder();
print "{argon2}${encoder.encode(args[0])}";