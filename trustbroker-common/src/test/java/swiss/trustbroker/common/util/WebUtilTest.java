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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.hc.client5.http.utils.DateUtils;
import org.hamcrest.CoreMatchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import swiss.trustbroker.common.dto.CookieParameters;

class WebUtilTest {

	private static final String TEST_URL = "https://localhost";

	private static final String TEST_QUERY = "one=uno&two=due&three=tre&two=deux";

	private static final String TEST_URL_WITH_QUERY = TEST_URL + '?' + TEST_QUERY;

	@Test
	void getUrlWithQuery() {
		var request = new MockHttpServletRequest();
		request.setRequestURI(TEST_URL);
		assertThat(WebUtil.getUrlWithQuery(request), is(TEST_URL));
		request.setQueryString(TEST_QUERY);
		assertThat(WebUtil.getUrlWithQuery(request), is(TEST_URL_WITH_QUERY));
	}

	@ParameterizedTest
	@CsvSource(value = {
			",''",
			"https://localhost,https%3A%2F%2Flocalhost"
	})
	void testUrlEncodeValue(String url, String expected) {
		assertThat(WebUtil.urlEncodeValue(url), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			",''",
			"https%3A%2F%2Flocalhost,https://localhost"
	})
	void testUrlDecodeValue(String url, String expected) {
		assertThat(WebUtil.urlDecodeValue(url), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			",false,false",
			"'',false,true",
			"/path,false,true",
			"http://localhost:1234/return/to?x=y,true,false",
			"myapp://launch,true,false",
	})
	void testIsValidRelativeAbsoluteUrl(String url, boolean absolute, boolean relative) {
		assertThat(WebUtil.isValidAbsoluteUrl(url), is(absolute));
		assertThat(WebUtil.isValidRelativeUrl(url), is(relative));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null",
			"https://example.trustbroker.swiss:8080/path?query=123,example.trustbroker.swiss",
			"https:localhost/bla,null"
	}, nullValues = "null")
	void testUrlHost(String url, String expected) {
		assertThat(WebUtil.getUrlHost(url), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"http://localhost/test,http://localhost",
			"https://test.trustbroker.swiss:443/test,https://test.trustbroker.swiss:443",
			"some,null"
	}, nullValues = "null")
	void testOrigin(String url, String expected) {
		var request = new MockHttpServletRequest();
		request.addHeader(HttpHeaders.REFERER, url);
		assertThat(WebUtil.getOriginOrReferer(request), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"NULL,false",
			"null,true",
			"https://localhost,false"
	}, nullValues = "NULL")
	void isNullOrigin(String origin, boolean expected) {
		assertThat(WebUtil.isNullOrigin(origin), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			// missing base or other
			"null,null,null",
			"null,/test,/test",
			"https://example.trustbroker.swiss,null,https://example.trustbroker.swiss",
			"null,https://example.trustbroker.swiss/test,https://example.trustbroker.swiss/test",
			// absolute other
			"https://example.trustbroker.swiss,https://localhost:8080/test,https://localhost:8080/test",
			"/base,https://localhost:8080/test,https://localhost:8080/test",
			// relative other, absolute base
			"https://example.trustbroker.swiss,/test,https://example.trustbroker.swiss/test",
			// relative base and other
			"/base,/test,/test"
	}, nullValues = "null")
	void testGetAbsoluteUrl(String baseUrl, String otherUrl, String expectedResult) {
		assertThat(WebUtil.getAbsoluteUrl(baseUrl, otherUrl), is(expectedResult));
	}

	@ParameterizedTest
	@MethodSource
	void testAppendQueryParameters(String query, Map<String, String> parameters, String expected) {
		assertThat(WebUtil.appendQueryParameters(query, parameters), is(expected));
	}

	static Object[][] testAppendQueryParameters() {
		// ensure predictable iteration order for the test
		var paramMap1 = new LinkedHashMap<String, String>();
		paramMap1.put("key1", "value1");
		paramMap1.put("key+", "this&that");

		var paramMap2 = new LinkedHashMap<String, String>();
		paramMap2.put("a", "");
		paramMap2.put("b", null);

		return new Object[][] {
				{ null, null, null },
				{ null, paramMap2, "?a=&b=" },
				{ TEST_URL, Collections.emptyMap(), TEST_URL },
				{ "https://localhost/test", paramMap1, "https://localhost/test?key1=value1&key%2B=this%26that" },
				{ "https://localhost/test?foo=bar", paramMap2, "https://localhost/test?foo=bar&a=&b=" }
		};
	}

	@ParameterizedTest
	@CsvSource(value = {
			"persistentCookie,sessionId1,300,true,true,domain.org,/foo,null,persistentCookie,sessionId1,300,true,true,domain.org,/foo,null",
			"sessionCookie,sessionId2,null,false,false,null,null,Lax,sessionCookie,sessionId2,-1,false,false,null,/,Lax",
			"sessionCookie,sessionId2,-1,false,false,null,,Strict,sessionCookie,sessionId2,-1,false,false,null,/,Strict",
			"sessionCookie,sessionId2,-1,false,false,,/path/to/app,None,sessionCookie,sessionId2,-1,false,false,null,/path/to/app,None",
			"sessionCookie,sessionId2,-1,false,false,,/path,Dynamic,sessionCookie,sessionId2,-1,false,false,null,/path,null"
	}, nullValues = "null")
	void testCreateCookie(String name, String sessionId, Integer lifeTime, boolean secure, boolean httpOnly, String domain,
			String path, String sameSite, String expectedName, String expectedSessionId, Integer expectedLifeTime,
			boolean expectedSecure, boolean expectedHttpOnly, String expectedDomain, String expectedPath, String expectedSameSite) {
		var params = CookieParameters.builder()
									 .name(name)
									 .value(sessionId)
									 .maxAge(lifeTime)
									 .secure(secure)
									 .httpOnly(httpOnly)
									 .domain(domain)
									 .path(path)
									 .sameSite(sameSite)
									 .build();
		var cookie = WebUtil.createCookie(params);
		assertThat(cookie.getName(), is(expectedName));
		assertThat(cookie.getValue(), is(expectedSessionId));
		assertThat(cookie.getMaxAge(), is(expectedLifeTime));
		assertThat(cookie.getSecure(), is(expectedSecure));
		assertThat(cookie.isHttpOnly(), is(expectedHttpOnly));
		assertThat(cookie.getDomain(), is(expectedDomain));
		assertThat(cookie.getPath(), is(expectedPath));
		assertThat(cookie.getAttribute(WebUtil.COOKIE_SAME_SITE), is(expectedSameSite));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null", // special origin value
			"NULL,NULL",
			",NULL",
			"foobar,NULL",
			"https://example.trustbroker.swiss,https://example.trustbroker.swiss",
			"https://example.trustbroker.swiss/,https://example.trustbroker.swiss",
			"https://example.trustbroker.swiss/path?query=value#fragment,https://example.trustbroker.swiss",
			"https://example.trustbroker.swiss:443,https://example.trustbroker.swiss:443",
			"custom://value,custom://value",
			"http://localhost:8080,http://localhost:8080"
	}, nullValues = "NULL") // capital on purpose due to null origin value
	void testGetValidOrigin(String origin, String expected) {
		assertThat(WebUtil.getValidOrigin(origin), CoreMatchers.is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,NULL", // special origin value ignored
			"NULL,NULL",
			",NULL",
			"foobar,NULL",
			"https://example.trustbroker.swiss,https://example.trustbroker.swiss/",
			"https://example.trustbroker.swiss/,https://example.trustbroker.swiss/",
			"https://example.trustbroker.swiss/path?query=value#fragment,https://example.trustbroker.swiss/",
			"https://example.trustbroker.swiss:443,https://example.trustbroker.swiss:443/",
			"custom://value,custom://value/",
			"http://localhost:8080,http://localhost:8080/"
	}, nullValues = "NULL") // capital on purpose due to null referer value
	void testGetValidRefererWithoutPath(String referer, String expected) {
		assertThat(WebUtil.getValidRefererWithoutPath(referer), CoreMatchers.is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null",
			"/path,null", // relative
			"://,null", // invalid
			"https://trustbroker.swiss,trustbroker.swiss",
			"https://sub.domain.trustbroker.swiss,trustbroker.swiss",
			"https://trustbroker.ch,trustbroker.ch",
			"https://test.trustbroker.ch,trustbroker.ch", // domain not under control of trustbroker.swiss
			"http://trustbroker.swiss:8080/test,trustbroker.swiss",
			"http://localhost/path,localhost", // extraction not implemented
			"http://sub.localhost.localdomain/path,sub.localhost.localdomain", // extraction not implemented
			"http://sub.trustbroker.co.uk/path,trustbroker.co.uk" // domain not under control of trustbroker.swiss
	}, nullValues = "null")
	void testGetSite(String url, String expected) {
		var uri = WebUtil.getValidatedUri(url);
		var result = WebUtil.getSite(uri);
		assertThat(result, is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,false",
			"https://trustbroker.swiss,null,false",
			"null,https://trustbroker.swiss,false",
			"Https://TrustBroker.swiss/Path1,HTTPS://TRUSTBROKER.SWISS/PATH2,true", // case is irrelevant
			"https://trustbroker.swiss/path1,https://trustbroker.swiss/path2,true",
			"https://trustbroker.swiss/path1,http://trustbroker.swiss/path2,false", // scheme mismatch
			"https://sub.one.trustbroker.swiss/path1,https://sub.two.trustbroker.swiss/path2,true",
			"http://localhost/path,https://localhost/test,false", // scheme mismatch
			"https://localhost/path,https://localhost:9090/test,true", // extraction not implemented
			"http://one.trustbroker.co.uk/a,http://two.trustbroker.co.uk/b,true" // domain not under control of trustbroker.swiss
			// not repeating all the extraction cases covered by testGetSite
	}, nullValues = "null")
	void testIsSameSite(String url1, String url2, boolean expected) {
		var uri1 = WebUtil.getValidatedUri(url1);
		var uri2 = WebUtil.getValidatedUri(url2);
		var result = WebUtil.isSameSite(uri1, uri2);
		assertThat(result, is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,null,None",
			"null,https://localhost,None",
			"https://foo.trustbroker.swiss/path1,https://bar.trustbroker.swiss/path2,Strict",
	}, nullValues = "null")
	void testGetCookieSameSite(String perimeterUrl, String requestUrl, String expected) {
		var result = WebUtil.getCookieSameSite(perimeterUrl, requestUrl);
		assertThat(result, is(expected));
	}

	@Test
	void testClientIp() {
		var singleIp = new MockHttpServletRequest();
		singleIp.addHeader(WebUtil.HTTP_HEADER_X_ORIGINAL_FORWARDED_FOR, "10.0.0.1");
		assertThat(WebUtil.getClientIp(singleIp), is("10.0.0.1/XOFF"));

		var proxyIps = new MockHttpServletRequest();
		proxyIps.addHeader(WebUtil.HTTP_HEADER_X_ORIGINAL_FORWARDED_FOR, "10.0.0.1, 10.0.0.2");
		assertThat(WebUtil.getClientIp(proxyIps, false), is("10.0.0.1"));

		var gatewayIp = new MockHttpServletRequest();
		gatewayIp.addHeader(WebUtil.HTTP_HEADER_X_ORIGINAL_FORWARDED_FOR, "10.0.0.1, 10.0.0.2");
		assertThat(WebUtil.getGatewayIp(gatewayIp), is("10.0.0.2"));
		assertThat(WebUtil.getGatewayIps(gatewayIp), is(List.of("10.0.0.1", "10.0.0.2")
															.toArray()));
		// override with simulation
		gatewayIp.addHeader(WebUtil.HTTP_HEADER_X_SIMULATED_FORWARDED_FOR, "10.0.0.3");
		assertThat(WebUtil.getGatewayIps(gatewayIp), is(List.of("10.0.0.3")
															.toArray()));
		assertThat(WebUtil.getClientIps(gatewayIp, false), is(List.of("10.0.0.1", "10.0.0.2")
																  .toArray()));

		var noIp = new MockHttpServletRequest();
		assertThat(WebUtil.getGatewayIp(noIp), is("127.0.0.1"));
		assertThat(WebUtil.getClientIp(noIp), is("127.0.0.1/SRA"));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,0,0,1000",
			"\"E199\",500,60,1000"
	}, nullValues = "null")
	void testAddCacheHeaders(String etag, int lastModifiedSecs, int maxAgeSecs, int nowSecs) {
		var response = new MockHttpServletResponse();
		var lastModified = Instant.ofEpochSecond(lastModifiedSecs);
		var expectedLastModified = lastModified != null ? DateUtils.formatStandardDate(lastModified) : null;
		var expectedPragma = maxAgeSecs > 0 ? "" : WebUtil.PRAGMA_NO_CACHE;
		var now = Instant.ofEpochSecond(nowSecs);
		var expires = Instant.ofEpochSecond(nowSecs + maxAgeSecs);
		var expectedExpires = maxAgeSecs == 0 ? "0" : DateUtils.formatStandardDate(expires);
		var expectedCacheControl = maxAgeSecs == 0 ? WebUtil.CACHE_CONTROL_NO_CACHE : WebUtil.CACHE_CONTROL_MAX_AGE + maxAgeSecs;

		WebUtil.addCacheHeaders(response, maxAgeSecs, etag, lastModified, now);

		assertThat(response.getHeader(HttpHeaders.ETAG), is(etag));
		assertThat(response.getHeader(HttpHeaders.LAST_MODIFIED), is(expectedLastModified));
		assertThat(response.getHeader(HttpHeaders.PRAGMA), is(expectedPragma));
		assertThat(response.getHeader(HttpHeaders.EXPIRES), is(expectedExpires));
		assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL), is(expectedCacheControl));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null;null;0;0;false",
			"\"E20AB\";\"B123\",\"E20AB\";0;0;true", // etag match
			"\"E20AB\";\"B123\",\"E20AB\";1000;100;true", // etag match wins
			"\"E20AB\";null;100;200;true", // modified since match
			"null;\"E20AB\";100;50;false", // modified since mismatch
	}, nullValues = "null", delimiter = ';')
	void testIsCached(String etag, String ifNoneMatch, int cacheTimeSecs, int ifModifiedSinceSecs, boolean expected) {
		var cacheTime = Instant.ofEpochSecond(cacheTimeSecs);
		var modified = Instant.ofEpochSecond(ifModifiedSinceSecs);
		var ifModifiedSince = ifModifiedSinceSecs == 0 ? null : DateUtils.formatStandardDate(modified);

		assertThat(WebUtil.isCached(etag, ifNoneMatch, cacheTime, ifModifiedSince), is(expected));
	}

}
