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

package swiss.trustbroker.sso.service;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import net.shibboleth.shared.security.RandomIdentifierParameterSpec;
import net.shibboleth.shared.security.impl.RandomIdentifierGenerationStrategy;
import org.apache.commons.codec.binary.Base64;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import swiss.trustbroker.common.exception.TechnicalException;

@Configuration
/**
 * Make SecureRandom injectable to allow mocking.
 */
@SuppressWarnings("java:S1118")
public class RandomProvider {

	@Bean
	public static RandomIdentifierGenerationStrategy randomIdGenerator() {
		try {
			// thread-safe: https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/SecureRandom.html
			var random = SecureRandom.getInstance("SHA1PRNG");
			// URL safe base64 in case it is ever an issue, no chunking with new lines:
			// thread-safe: https://commons.apache.org/proper/commons-codec/apidocs/org/apache/commons/codec/binary/Base64.html
			var coder = new Base64(0, null, true);
			// thread-safe due to only final thread-safe members
			var spec = new RandomIdentifierParameterSpec(random,60, coder);
			return new RandomIdentifierGenerationStrategy(spec);
		}
		catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | RuntimeException ex) {
			throw new TechnicalException("Cannot instantiate RandomIdentifierGenerationStrategy", ex);
		}
	}

}
