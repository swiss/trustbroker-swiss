/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

package swiss.trustbroker.common.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import org.junit.jupiter.api.Test;

class StringUtilTest {

	@Test
	void testCleanNull() {
		assertThat(StringUtil.clean(null), nullValue());
	}

	@Test
	void testCleanUnchanged() {
		var unproblematicText = "foo bar";
		assertThat(StringUtil.clean(unproblematicText), is(unproblematicText));
	}

	@Test
	void testCleanWhitespace() {
		var problematicText = "space\nthe\tfinal\rfrontier";
		assertThat(StringUtil.clean(problematicText), is("space_the_final_frontier"));
	}

	@Test
	void testCleanWhitespaceWithSpace() {
		var problematicText = "space\nthe\tfinal\rfrontier";
		assertThat(StringUtil.clean(problematicText, " "), is("space the final frontier"));
	}

	@Test
	void testMaskSecret() {
		assertThat(StringUtil.maskSecret(null), is(StringUtil.NULL));
		assertThat(StringUtil.maskSecret("test"), is(StringUtil.MASKED));
	}

	@Test
	void testMaskSecrets() {
		assertThat(StringUtil.maskSecrets(null, "one"), is(nullValue()));
		assertThat(StringUtil.maskSecrets("one,two,three,four,five","two", "five"),
				is("one," + StringUtil.MASKED + ",three,four," + StringUtil.MASKED));
	}

	@Test
	void testMaskSecretByKey() {
		assertThat(StringUtil.maskSecret("client_secret", "verySecretValue"), is("veryS***"));
		assertThat(StringUtil.maskSecret("ACCESS_TOKEN", "abc123token"), is("abc12***"));
		assertThat(StringUtil.maskSecret("auth_code", "abcd"), is("abcd***"));
		assertThat(StringUtil.maskSecret("scope", "openid profile"), is("openid profile"));
		assertThat(StringUtil.maskSecret("scope", null), is(""));
	}

	@Test
	void testCleanForNameValueMultipleUseCases() {
		assertThat(StringUtil.cleanForNameValue(null), is(""));
		assertThat(StringUtil.cleanForNameValue("plainText123"), is("plainText123"));
		assertThat(StringUtil.cleanForNameValue("line1\nline2\r\tend"), is("line1?line2??end"));
		assertThat(StringUtil.cleanForNameValue("<script>alert('x')</script>"), is("?script?alert(?x?)?/script?"));
		assertThat(StringUtil.cleanForNameValue("name=va\\lue;\"test\""), is("name=va?lue??test?"));
	}
}
