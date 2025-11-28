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

package swiss.trustbroker.saml.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Optional;

import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import swiss.trustbroker.saml.util.ClaimSourceUtil;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.STRICT_STUBS)
class ClaimSourceUtilTest {

	@ParameterizedTest
	@CsvSource(value = {
			"CP,CP,null",
			"CP:issuer,CP,issuer",
			"CP:issuer:01,CP,issuer:01",
			"CP:issuer:CP:01,CP,issuer:CP:01",
			"IDM:issuer:01:CP:01,CP,null",
	}, nullValues = "null")
	void getSecondarySourceTest(String source, String sourceName, String expectedSource) {
		if (expectedSource == null) {
			assertEquals(Optional.empty(), ClaimSourceUtil.getSecondarySource(source, sourceName));
		}
		else {
			assertEquals(Optional.of(expectedSource), ClaimSourceUtil.getSecondarySource(source, sourceName));
		}
	}
}
