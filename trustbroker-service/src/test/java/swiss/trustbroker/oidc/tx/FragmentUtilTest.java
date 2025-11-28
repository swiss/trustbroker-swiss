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

package swiss.trustbroker.oidc.tx;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.mock.web.MockHttpSession;

class FragmentUtilTest {

	@ParameterizedTest
	@CsvSource(value = {
			"https://host\\some|other?query=z,https://host\\some|other?query=z", // no change
			"https://host?query=z&code=x&state=y, https://host?query=z#code=x&state=y", // single standard query parameter
			"https://host?code=x&state=y, https://host#code=x&state=y", // no query params case, standard
			"https://host?code=x&state=y?query=z, https://host?query=z#code=x&state=y", // query params case, swap
			"https://host?code=x&state=y#fragment=z, https://host#fragment=z&code=x&state=y", // fragment params case, swap
			"https://host?code=x&state=y?query=z#fragment=z, https://host?query=z#fragment=z&code=x&state=y", // both, swap
			"https://host?query=z&code=x&state=y#fragment=z, https://host?query=z#fragment=z&code=x&state=y", // both, swap
			"https://host?code=x&state=y#fragment=z?query=z, https://host#fragment=z?query=z&code=x&state=y", // !RFC3986, swap
			// !RFC3986, swap
			"https://host?code=x#?query=z, https://host#?query=z&code=x", // !RFC3986, swap as is
			"https://host?error=x&error_uri=https%3A%2F%2Fhost%2Fapp%2Ffailure#?fragment=z," +
					"https://host#?fragment=z&error=x&error_uri=https%3A%2F%2Fhost%2Fapp%2Ffailure" // fragmented error redirects
	})
	void reorganizeRedirectUri(String inputLocation, String expectedLocation) {
		var ownParamPos = FragmentUtil.ownParametersPosition(inputLocation);
		assertThat(FragmentUtil.reorganizeRedirectUri(inputLocation, ownParamPos), is(expectedLocation));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"https://host?error=a, https://host?error=a", // leave alone
			"https://host?error=a&error_uri=c, https://host?error=a&error_uri=c", // leave alone
			"https://host?error=a&error=b&error_uri=c&error_uri=c, https://host?error=a&error_uri=c", // optimize
			"https://host?error=a&error=b&error_uri=c&error_uri=c&error_description=d&error_description=e,"
					+ "https://host?error=a&error_uri=c&error_description=d", // optimize
			"https://host?code=some&state=s&error=a&error_uri=c, https://host?code=some&state=s", // discard
			"https://host?error=a&error_uri=c&code=some, https://host?code=some", // discard
			"https://host?error=a&error_uri=c#code=some, https://host#code=some", // discard
			"https://host#code=some&error=a&error_uri=c, https://host#code=some", // discard
			"https://host#code=some&error=a&error_urI=c, https://host#code=some", // discard - case insensitive
			"https://host#error=a&error_uri=c&code=some, https://host#code=some" // discard
	})
	void discardAmbiguousErrorsInRedirect(String inputLocation, String expectedLocation) {
		var errorPos = FragmentUtil.ownParametersPosition(inputLocation, "error=");
		var codePos = FragmentUtil.ownParametersPosition(inputLocation, "code=");
		assertThat(FragmentUtil.discardAmbiguousErrorsInRedirect(inputLocation, errorPos, codePos >= 0), is(expectedLocation));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"https://host?error=a, https://host?error=a", // leave alone
			"https://host?error=a&error_uri=c, https://host", // discard
			"https://host?error=a&error=b&error_uri=c&error_uri=c, https://host", // discard
			"https://host?error=a&error=b&error_uri=c&app-param=some, https://host?app-param=some", // discard
			"https://host?error=a&error=b&Error_Uri=c&app-param=some, https://host?app-param=some", // discard - case insensitive
			"https://host?error=a&error=b&error_uri=c&error_uri=c&error_description=d&error_description=e, https://host"
	})
	void discardAAllErrorsInRedirect(String inputLocation, String expectedLocation) {
		assertThat(FragmentUtil.discardAllErrorsInRedirect(inputLocation), is(expectedLocation));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"query, https://host?code=some&state=s&error=a&error_uri=c, https://host?code=some&state=s",
			"form_post, https://host?code=some&state=s&error=a&error_uri=c, https://host?code=some&state=s",
			"fragment, https://host?code=some&state=s&error=a&error_uri=c, https://host#code=some&state=s",
			"fragment, https://host?code=some&state=s&eRRor=a&error_uri=c, https://host#code=some&state=s", // case insensitive
			"fragment, https://host?code=some&state=s&error=a&eRRor_uri=c, https://host#code=some&state=s", // case insensitive
			"any, https://host?error=a&error_uri=c&error=a&error_uri=c&code=some&state=s, https://host?code=some&state=s",
	})
	void checkAndFixRedirectUri(String mode, String inputLocation, String expectedLocation) {
		var session = new MockHttpSession();
		session.setAttribute(FragmentUtil.OIDC_RESPONSE_MODE, mode);
		assertThat(FragmentUtil.checkAndFixRedirectUri(inputLocation, session, mode), is(expectedLocation));
	}

	@Test
	void illegalUriParsing() throws URISyntaxException {
		var uri1 = new URI("https://host/#?query=x"); // illegal according to RFC3986
		assertThat(uri1.getQuery(), nullValue());
		assertThat(uri1.getFragment(), is("?query=x"));

		var uri2 = new URI("https://host/?query=x#?fragment=y");
		assertThat(uri2.getQuery(), is("query=x"));
		assertThat(uri2.getFragment(), is("?fragment=y"));
	}

}
