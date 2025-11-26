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

package swiss.trustbroker.oidc.cache.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.federation.xmlconfig.OidcClient;

/**
 * Client-side OIDC functionality.
 */
@Service
@Slf4j
class OidcClientSecretResolver {

	// client secret encodings

	static final String CLIENT_SECRET_PLAIN = "{noop}";

	static final String CLIENT_SECRET_FROM_FILE = "{file}";

	// Client secrets XTB sends to a CP cannot use one way encodings like ARGON2 etc.
	// Plain text secrets (prefix '{noop}') and secrets stored in a file (prefix '{file}') are currently supported.
	// The latter can be mapped e.g. from a password vault.
	public String resolveClientSecret(OidcClient client) {
		var clientSecret = client.getClientSecret();
		if (clientSecret == null) {
			return null;
		}
		if (clientSecret.startsWith(CLIENT_SECRET_PLAIN)) {
			log.debug("Using noop clientId={} secret", client.getId());
			return clientSecret.substring(CLIENT_SECRET_PLAIN.length());
		}
		if (clientSecret.startsWith(CLIENT_SECRET_FROM_FILE)) {
			var path = clientSecret.substring(CLIENT_SECRET_FROM_FILE.length());
			log.debug("Using client={} secret from file={}", client.getId(), path);
			try {
				return Files.readString(Path.of(path));
			}
			catch (IOException ex) {
				throw new TechnicalException(
						String.format("Unable to read client=%s secret from file=%s", client.getId(), path), ex);
			}
		}
		log.error("Client={} secret has unknown type, using as-is", client.getId());
		return clientSecret;
	}
}
