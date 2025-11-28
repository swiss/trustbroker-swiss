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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.oidc.OidcMockTestData;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class OidcClientSecretResolverTest {

	private static final String CLIENT_SECRET_FILE = "testSecret.txt";

	private OidcClientSecretResolver clientSecretResolver = new OidcClientSecretResolver();

	@Test
	void resolveClientSecretPlain() {
		var clientNoSecret = OidcMockTestData.givenClientWithSecret(null);
		assertThat(clientSecretResolver.resolveClientSecret(clientNoSecret), is(nullValue()));
		var client = OidcMockTestData.givenClientWithSecret(
				OidcClientSecretResolver.CLIENT_SECRET_PLAIN + OidcMockTestData.CLIENT_SECRET);
		assertThat(clientSecretResolver.resolveClientSecret(client), is(OidcMockTestData.CLIENT_SECRET));
	}

	@Test
	void resolveClientSecretFromFile() {
		var filePath = SamlTestBase.filePathFromClassPath(CLIENT_SECRET_FILE);
		var client = OidcMockTestData.givenClientWithSecret(OidcClientSecretResolver.CLIENT_SECRET_FROM_FILE + filePath);
		assertThat(clientSecretResolver.resolveClientSecret(client), is(OidcMockTestData.CLIENT_SECRET));
		var invalidClient = OidcMockTestData.givenClientWithSecret(
				OidcClientSecretResolver.CLIENT_SECRET_FROM_FILE + filePath + ".unknown");
		assertThrows(TechnicalException.class, () -> clientSecretResolver.resolveClientSecret(invalidClient));
	}

	@Test
	void  resolveClientSecretWithoutScheme() {
		var client = OidcMockTestData.givenClientWithSecret(OidcMockTestData.CLIENT_SECRET);
		assertThat(clientSecretResolver.resolveClientSecret(client), is(OidcMockTestData.CLIENT_SECRET));
	}

}
