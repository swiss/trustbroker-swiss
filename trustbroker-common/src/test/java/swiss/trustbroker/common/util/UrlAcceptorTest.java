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

package swiss.trustbroker.common.util;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Set;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class UrlAcceptorTest {

	@ParameterizedTest
	@CsvSource(value = {
			"http://test.trustbroker.swiss,true",
			"http://test.trustbroker.swiss/path,true",
			"http://test,false",
			"http://t,false",
			"https://test.trustbroker.swiss,false",
			"https://example.trustbroker.swiss/bar/,true",
			"http://localhost,true",
			"http://user1@localhost,false",
			"https://localhost,true",
			"https://localhost:5220,true",
			"https://localhost:5220/,true",
			"http://127.0.0.1:5220,false",
			"https://127.0.0.1:5220,true",
			"https://127.0.0.1:5220/,true"
	})
	void isTrustedOriginTest(String url, boolean expected) {
		Set<String> redirectUris = Set.of(
				"http://test.trustbroker.swiss/.*",  // includes http://test.trustbroker.swiss
				"https://example.trustbroker.swiss/foo/.*",  // path ignored for origin
				"https://localhost:0", // special matching for localhost
				"http://localhost:?([0-9]*?)/?" // regex match, does not consider localhost variants
		);
		assertThat(UrlAcceptor.isTrustedOrigin(url, redirectUris), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// invalid
			"null,null,false,false",
			"https://localhost,null,false,false",
			"null,https://localhost,false,false",
			"invalid,invalid,false,false",
			// https port
			"https://localhost,https://localhost,false,true",
			"https://localhost:443,https://localhost,false,true",
			"https://localhost,https://localhost:443,false,true",
			"https://localhost:443,https://localhost:443,false,true",
			"https://localhost:443,https://localhost:80,false,false",
			"https://localhost:80,https://localhost:443,false,false",
			"https://localhost:80,https://localhost:0,false,true",
			// http port
			"http://localhost,http://localhost:80,false,true",
			// path
			"https://example.trustbroker.swiss/path/same,https://example.trustbroker.swiss/path/same,false,true",
			"https://example.trustbroker.swiss/path/notsame,https://example.trustbroker.swiss/path/differs,false,false",
			"https://example.trustbroker.swiss:443/path/anything,https://example.trustbroker.swiss/path/.*,false,true",
			"https://example.trustbroker.swiss:443/path,https://example.trustbroker.swiss/path/.*,false,true",
			"https://example.trustbroker.swiss/path2/anything,https://example.trustbroker.swiss/path/.*,false,false",
			"https://example.trustbroker.swiss/path/this.html,https://example.trustbroker.swiss:443/path/th.*html,false,true",
			"https://example.trustbroker.swiss/path/that.html,https://example.trustbroker.swiss:443/path/th.*html,false,true",
			"https://example.trustbroker.swiss/path/that.php,https://example.trustbroker.swiss:443/path/th.*html,false,false",
			// regexp in path
			"https://host/admin0,https://host/admin[0-9]/.*,false,false", // regexp does not parse
			"https://host/admin1/,https://host/admin./.*,false,true",
			"https://host/admin2/x,https://host/admin./.+,false,true",
			"https://host/admin3/some,https://host/admin./.*,false,true",
			// origin matching (we use referrer as fallback, so test also with / or a path)
			"https://example.trustbroker.swiss,https://example.trustbroker.swiss:443/path/th.*html,true,true",
			"https://example.trustbroker.swiss/,https://example.trustbroker.swiss:443/path/th.*html,true,true",
			"https://example.trustbroker.swiss/other,https://example.trustbroker.swiss:443/path/th.*html,true,true",
			"https://localhost:80,https://localhost:0/path,true,true",
			"https://localhost:80/,https://localhost:0/path,true,true",
			"https://localhost:80/other,https://localhost:0/path,true,true",
			// custom scheme
			"myapp://redirect,myapp://redirect,false,true"
	}, nullValues = "null")
	void testUrlOkForAccess(String check, String accept, boolean ignorePath, boolean expected) {
		assertThat(UrlAcceptor.isUrlOkForAccess(check, accept, ignorePath), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// localhost
			"https://localhost,https://localhost,true",
			"https://localhost,https://localhost/.*,true",
			"https://localhost:443,https://localhost/.*,true",
			"https://localhost,https://localhost:443/.*,true",
			"https://127.0.0.1,https://localhost:443/.*,true",
			"https://user@127.0.0.1,https://localhost:443/.*,false",
			"https://user:pw@127.0.0.1,https://localhost:443/.*,false",
			"https://localhost:80,https://localhost:443,false",
			"https://localhost:80,https://localhost:0,true",
			"https://localhost:80,https://localhost:.*/.*,true", // should not run into urlOkForAccess (URI.getPort is an int)
			// Sub-path ok by accepting /.* as nothing
			"https://example.trustbroker.swiss/path/same,https://example.trustbroker.swiss/path/same,true",
			"https://example.trustbroker.swiss/path/same,https://example.trustbroker.swiss/path/same/.*,true",
			"https://example.trustbroker.swiss/path/other,https://example.trustbroker.swiss/path/same/.*,false"
	}, nullValues = "null")
	void testRedirectUriOkForAccess(String check, String accept, boolean expected) {
		assertThat(UrlAcceptor.isRedirectUrlOkForAccess(check, Set.of(accept)), is(expected));
	}

}
