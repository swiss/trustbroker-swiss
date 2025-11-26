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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.Optional;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class AuthorizedApplicationTest {

	@ParameterizedTest
	@CsvSource(value = { "null,false", "'',false", "/path,true" }, nullValues = "null")
	void checkUrl(String url, boolean match) {
		var application = AuthorizedApplication.builder().url(url).build();
		assertThat(application.checkUrl(), is(match));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,false", "'',null,false", "/path,null,false", "/path,http://localhost,false",
			"/path,http://localhost/path,true","/path,http://localhost/path/subpath,true"
	}, nullValues = "null")
	void urlMatching(String url, String referrer, boolean match) {
		var application = AuthorizedApplication.builder().url(url).build();
		assertThat(application.urlMatching(referrer), is(match));
	}

	@ParameterizedTest
	@CsvSource(value = { "null,false", "10,true" }, nullValues = "null")
	void checkQoa(Integer qoa, boolean match) {
		var application = AuthorizedApplication.builder().minQoa(qoa).build();
		assertThat(application.checkQoa(), is(match));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,false", "10,null,false", "20,10,false",
			"20,20,true", "20,30,false"
	}, nullValues = "null")
	void qoaMatching(Integer qoa, Integer inputQoa, boolean match) {
		var optQoa = Optional.ofNullable(inputQoa);
		var application = AuthorizedApplication.builder().minQoa(qoa).build();
		assertThat(application.qoaMatching(optQoa), is(match));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// none required (= default application)
			"null,null,null,null,false,true",
			"null,http://any,null,30,false,true",
			// url only
			"/path,http://localhost/path/,null,null,true,false",
			"/path,http://localhost/path/,null,20,true,false",
			"/path,http://localhost,null,null,false,false",
			"/path,http://localhost/other,null,null,false,false",
			"/path,null,null,null,false,false",
			// qoa only
			"null,null,20,20,true,false",
			"null,http://localhost/any,60,60,true,false",
			"null,null,20,10,false,false",
			"null,http://localhost/ok,50,40,false,false",
			"null,null,20,null,false,false",
			// url and qoa
			"/path,http://localhost/path,20,20,true,false",
			"/path,http://localhost/other,20,10,false,false",
			"/path,http://localhost/other,20,20,false,false"
	}, nullValues = "null")
	void matchUrlAndQoa(String url, String referrer, Integer qoa, Integer inputQoa, boolean match, boolean defaultApplication) {
		var optQoa = Optional.ofNullable(inputQoa);
		var application = AuthorizedApplication.builder().minQoa(qoa).url(url).build();
		assertThat(application.matchUrlAndQoa(referrer, optQoa), is(match));
		assertThat(application.isDefaultApplication(), is(defaultApplication));
	}


	@ParameterizedTest
	@CsvSource(value = {
			// none required (= default application)
			"null,null,null,false,true",
			// name
			"null,null,app1,false,false",
			// clientId
			"client1,client1,null,true,false",
			"client1,null,client1,false,false",
			"client1,client2,client2,true,false",
			"client1,client1,client2,true,false",
	}, nullValues = "null")
	void matchClientId(String clientId, String inputClientId, String name, boolean match, boolean defaultApplication) {
		var application = AuthorizedApplication.builder().name(name).clientId(clientId).build();
		assertThat(application.isDefaultApplication(), is(defaultApplication));
		assertThat(application.matchClientId(inputClientId), is(match));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// none required
			"null,null,null,null,null,null,null,null,true",
			"null,http://any,null,30,null,null,null,null,true",
			// url only
			"/path,null,null,null,null,null,null,null,true",
			"/path,null,null,20,null,null,null,null,true",
			"/path,http://localhost/path,null,30,null,null,null,null,false",
			"/path,http://localhost/other,null,40,null,null,null,null,false",
			// qoa only
			"null,null,20,null,null,null,null,null,true",
			"null,http://localhost/any,60,null,null,null,null,null,true",
			"null,null,20,30,null,null,null,null,false",
			"null,http://localhost/ok,50,40,null,null,null,null,false",
			// url and qoa
			"/path,null,20,null,null,null,null,null,true",
			"/path,http://localhost/path,20,30,null,null,null,null,false",
			// applicationName
			"null,null,null,null,null,null,app1,null,true",
			"null,null,null,null,null,null,null,app1,true",
			"null,null,null,null,null,null,app1,app2,false",
			// clientId
			"null,null,null,null,null,app1,null,null,true",
			"null,null,null,null,app2,null,null,null,true",
			"null,null,null,null,app2,app1,null,null,false"
	}, nullValues = "null")
	void noCheckOrEmpty(String url, String referrer, Integer qoa, Integer inputQoa, String clientId, String inputClientId,
			String name, String applicationName, boolean result) {
		var optQoa = Optional.ofNullable(inputQoa);
		var application = AuthorizedApplication.builder().name(name).minQoa(qoa).url(url).clientId(clientId).build();
		assertThat(application.noCheckOrEmpty(referrer, optQoa, inputClientId, applicationName), is(result));
	}
}
