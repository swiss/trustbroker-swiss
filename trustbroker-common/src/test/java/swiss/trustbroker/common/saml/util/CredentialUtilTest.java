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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.common.exception.TechnicalException;

class CredentialUtilTest {

	@Test
	void processPassword() {
		assertThat(CredentialUtil.processPassword(null), is(nullValue()));
		assertThat(CredentialUtil.processPassword("test"), is("test"));
		// we cannot modify System.getenv
		assertThrows(TechnicalException.class, () -> CredentialUtil.processPassword("$PASSWORD"));
	}

	@Test
	void passwordToCharArray() {
		assertThat(CredentialUtil.passwordToCharArray(null), is(nullValue()));
		assertThat(CredentialUtil.passwordToCharArray(""), is(new char[0]));
		assertThat(CredentialUtil.passwordToCharArray("pwd"), is("pwd".toCharArray()));
	}
}
