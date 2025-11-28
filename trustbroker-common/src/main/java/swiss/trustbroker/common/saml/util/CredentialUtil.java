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

package swiss.trustbroker.common.saml.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import swiss.trustbroker.common.exception.TechnicalException;

public class CredentialUtil {

	private CredentialUtil() {}

	public static String processPassword(String password) {
		if (password != null && password.startsWith("$")) {
			String passwordFromEnv = System.getenv(password.substring(1));
			if (passwordFromEnv == null) {
				String msg = String.format("Missing password in env: %s", password);
				throw new TechnicalException(msg);
			}
			return passwordFromEnv;
		}
		return password;
	}

	/**
	 * @param optionalPassword password or null
	 * @return password characters or null
	 */
	@SuppressWarnings("java:S1168") // need to return null array if there is no password
	public static char[] passwordToCharArray(String optionalPassword) {
		if (optionalPassword == null) {
			return null;
		}
		return optionalPassword.toCharArray();
	}

	public static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}
}
