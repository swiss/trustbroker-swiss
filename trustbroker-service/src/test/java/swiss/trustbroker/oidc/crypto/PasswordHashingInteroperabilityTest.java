/*
 * Copyright (C) 2024 trustbroker.swiss team BIT
 *
 * This program is free software.
 * You can redistribute it and/or modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the GNU Affero General Public License for more details.
 * You should have received a copy of the GNU Affero General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 */

package swiss.trustbroker.oidc.crypto;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

// Test using out from Python script trustbroker-swiss/trustbroker-service/etc/crypto/hashGeneratorForTests.py
class PasswordHashingInteroperabilityTest {

	private static PasswordEncoder getHashingFunctions() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Test
	void scryptHashingTest() {
		var clientSecretPairs = new HashMap<String, String>();
		clientSecretPairs.put("secret", "{scrypt}" + "$b0801$XeyVNpO35S0kUB2VT94GYQ==$6wAwSaXh1KfAU9pOxen+fMBUe+J5BQv4l0FirO16R78=");
		clientSecretPairs.put("test01", "{scrypt}" + "$b0801$BPbnAUtDaWj3w/Rcd09iWg==$BM7DY3nV2oGZRvDa8yKi8ylNm8e4q4YoHXOmjwO6Hj0=");

		PasswordEncoder hashingFunction = getHashingFunctions();
		for (Map.Entry<String, String> map : clientSecretPairs.entrySet()) {
			var password = map.getKey();
			var hash = map.getValue();
			assertTrue(hashingFunction.matches(password, hash));
			assertFalse(hashingFunction.matches(password + "1", hash));
			assertFalse(hashingFunction.matches(password, "{scrypt}" +
					"$b0801$6rxuzvb/gh6jZJxLw/5Q2Q==$48oXwiQP3Fqda6wTjmRd3KJwmwmeYKfv6eq/IFzCpCE="));
		}
	}

	@Test
	void pbkdf2HashingTest() {
		var clientSecretPairs = new HashMap<String, String>();
		clientSecretPairs.put("secret", "{pbkdf2@SpringSecurity_v5_8}" +
				"57b2970d81fa9f77f1eae65e82caa4b2548edf70a07857fe9fba74328adbfda8d00b2191906b0fa19106aeb2cba90940");
		clientSecretPairs.put("test01", "{pbkdf2@SpringSecurity_v5_8}" +
				"57b2970d81fa9f77f1eae65e82caa4b2f70f760797205a2838cfe5e1816a7d8cb539d2f39c354023e12c945ccbcf2f00");

		PasswordEncoder hashingFunction = getHashingFunctions();
		for (Map.Entry<String, String> map : clientSecretPairs.entrySet()) {
			var password = map.getKey();
			var hash = map.getValue();
			assertTrue(hashingFunction.matches(password, hash));
			assertFalse(hashingFunction.matches(password + "1", hash));
			assertFalse(hashingFunction.matches(password, "{pbkdf2@SpringSecurity_v5_8}" +
					"76b7a6aa6bb543d631ebea02bf1c9e76c4eff24ed7dbfc4b8b573bbce91b8103"));
		}
	}

	@Test
	void argon2HashingTest() {
		var clientSecretPairs = new HashMap<String, String>();
		clientSecretPairs.put("secret",
				"{argon2}" + "$argon2id$v=19$m=65536,t=3,p=4$CcEXdROFJ5XQAFJhXQF9ag$TXIac73rwM/u9PK+Lz38O1YjHRy46l7PkXdDuZ7RXC8");
		clientSecretPairs.put("test01",
				"{argon2}" + "$argon2id$v=19$m=65536,t=3,p=4$ZNZiLOJ6cZdIhowPWSWcRQ$Ws4QwZhnDdAB4j4JvwEkuf1xtCcZJLc9YSY58XZ/aJk");

		PasswordEncoder hashingFunction = getHashingFunctions();
		for (Map.Entry<String, String> map : clientSecretPairs.entrySet()) {
			var password = map.getKey();
			var hash = map.getValue();
			assertTrue(hashingFunction.matches(password, hash));
			assertFalse(hashingFunction.matches(password + "1", hash));
			assertFalse(hashingFunction.matches(password, "{argon2}" +
					"$argon2id$v=19$m=65536,t=3,p=4$dpqg8bDN6kjZJeqorMzbrw$Elkh/hYq16w8pXFm3s+aclEe3ZOdtXVE1SXcDkC9MR0"));
		}
	}

}
