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

package swiss.trustbroker.federation.xmlconfig;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class HomeNameTest {

	@ParameterizedTest
	@MethodSource
	void getName(HomeName homeName, String expected) {
		assertThat(homeName.getName(), is(expected));
	}

	static Object[][] getName() {
		return new Object[][] {
				{ HomeName.builder().build(), "" },
				{ HomeName.builder().value("value1").build(), "value1" },
				{ HomeName.builder().attrValue("value2").build(), "value2" },
				{ HomeName.builder().value("").attrValue("value2").build(), "value2" }
		};
	}

}
