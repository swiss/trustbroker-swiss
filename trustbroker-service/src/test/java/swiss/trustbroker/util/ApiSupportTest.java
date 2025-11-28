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

package swiss.trustbroker.util;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.common.saml.util.Base64Util;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.OidcProperties;

class ApiSupportTest {

	private static final String BASE_URL = "http://localhost:4200";

	private static final String PERIMETER_URL = "http://localhost:8080";

	private static final String OIDC_PERIMETER_URL = "http://auth-server:8080";

	private static final String GROUP_NAME = "SSO1";

	private static final String ISSUER_1_ID = "http://issuer.trustbroker.swiss/?x";

	private static final String ISSUER_1_ENCODED = Base64Util.urlEncode(ISSUER_1_ID);

	private static final String ISSUER_2_ID = "http://cp.issuer.trustbroker.swiss/?x";

	private static final String ISSUER_2_ENCODED = Base64Util.urlEncode(ISSUER_2_ID);

	private static final String SUBJECT_NAME_ID = "user123";

	// standard base64(SUBJECT_NAME_ID) is dXNlcjEyMwo=
	private static final String SUBJECT_NAME_ID_ENCODED = "dXNlcjEyMw";

	private static final String REQUEST_ID = "7350babf-1431-4049-969b-34ba06f076d2";

	private static final String VERSION_INFO = "XTB/9.8.7.654321@TEST";

	private ApiSupport apiSupport;

	@BeforeEach
	void setUp() {
		setupApi(BASE_URL, PERIMETER_URL, OIDC_PERIMETER_URL);
	}

	private void setupApi(String baseUrl, String perimeterUrl, String oidcPerimeterUrl) {
		var trustBrokerProperties = new TrustBrokerProperties();
		trustBrokerProperties.setFrontendBaseUrl(baseUrl);
		trustBrokerProperties.setPerimeterUrl(perimeterUrl);
		trustBrokerProperties.setVersionInfo(VERSION_INFO);
		var oidc = new OidcProperties();
		oidc.setPerimeterUrl(oidcPerimeterUrl);
		trustBrokerProperties.setOidc(oidc);
		apiSupport = new ApiSupport(trustBrokerProperties);
	}

	@Test
	void testEncodeUrlParameter() {
		assertThat(ApiSupport.encodeUrlParameter(ISSUER_1_ID), is(ISSUER_1_ENCODED));
	}

	@Test
	void testEncodeNullUrlParameter() {
		assertThat(ApiSupport.encodeUrlParameter(null), is(nullValue()));
	}

	@Test
	void testDecodeUrlParameter() {
		assertThat(ApiSupport.decodeUrlParameter(ISSUER_1_ENCODED), is(ISSUER_1_ID));
	}


	@Test
	void testDecodeNullParameter() {
		assertThat(ApiSupport.decodeUrlParameter(null), is(nullValue()));
	}

	@Test
	void testDecodeParameterCleaned() {
		var encoded = "dGVzdAo"; // base64("test\n")
		assertThat(ApiSupport.decodeUrlParameter(encoded), is("test_"));
	}

	@Test
	void testGetHrdUrl() {
		assertThat(apiSupport.getHrdUrl(ISSUER_1_ID, REQUEST_ID),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.HRD_PAGE + '/' + ISSUER_1_ENCODED + '/' + REQUEST_ID));
	}

	@Test
	void testGetDeviceInfoUrl() {
		assertThat(apiSupport.getDeviceInfoUrl(ISSUER_1_ID, ISSUER_2_ID, REQUEST_ID),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.DEVICE_INFO_PAGE + '/' + ISSUER_1_ENCODED + '/'
						+ ISSUER_2_ENCODED + '/' + REQUEST_ID));
	}

	@Test
	void testGetErrorPageUrl() {
		assertThat(apiSupport.getErrorPageUrl("denied", REQUEST_ID),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.ERROR_PAGE + "/denied/" + REQUEST_ID));
	}

	@Test
	void testGetErrorPageUrlWithNullTraceId() {
		assertThat(apiSupport.getErrorPageUrl("denied", null),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.ERROR_PAGE + "/denied"));
	}

	@Test
	void testGetErrorPageUrlWithFlags() {
		var sessionId = "authnRequestId1";
		assertThat(apiSupport.getErrorPageUrlWithFlags("disabled", REQUEST_ID, sessionId, List.of("first", "second")),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.ERROR_PAGE + "/disabled/"
						+ REQUEST_ID + "/" + ApiSupport.encodeUrlParameter(sessionId) + "/first_second"));
	}

	@Test
	void testGetDefaultErrorPageUrl() {
		assertThat(apiSupport.getErrorPageUrl(),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.ERROR_PAGE));
	}

	@Test
	void testGetProfileSelectionUrl() {
		assertThat(apiSupport.getProfileSelectionUrl(REQUEST_ID),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.PROFILE_SELECTION_PAGE + '/' + REQUEST_ID));
	}

	@Test
	void testGetDefaultSsoUrl() {
		assertThat(apiSupport.getSsoUrl(), is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.SSO_PAGE));
	}

	@Test
	void testGetSsoUrl() {
		assertThat(apiSupport.getSsoUrl(GROUP_NAME),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.SSO_PAGE + '/' + GROUP_NAME));
	}

	@Test
	void testGetAnnouncementsUrl() {
		var appName = "appName";
		var encodedAppName = Base64Util.urlEncode(appName);
		assertThat(apiSupport.getAnnouncementsUrl(ISSUER_1_ID, REQUEST_ID, appName),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.ANNOUNCEMENTS_PAGE + '/' + ISSUER_1_ENCODED + '/' + REQUEST_ID + '/' + encodedAppName));
	}

	@Test
	void testGetAnnouncementsUrlNoAppName() {
		assertThat(apiSupport.getAnnouncementsUrl(ISSUER_1_ID, REQUEST_ID, null),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.ANNOUNCEMENTS_PAGE + '/' + ISSUER_1_ENCODED + '/' + REQUEST_ID));
	}

	@Test
	void testGetAccessRequestInitiateUrl() {
		assertThat(apiSupport.getAccessRequestInitiateUrl(REQUEST_ID),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.ACCESS_REQUEST_PAGE + '/' + REQUEST_ID + ApiSupport.INITIATE_POSTFIX));
	}

	@Test
	void testGetAccessRequestInPogressUrl() {
		assertThat(apiSupport.getAccessRequestInProgressUrl(REQUEST_ID),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.ACCESS_REQUEST_PAGE + '/' + REQUEST_ID + ApiSupport.PROGRESS_POSTFIX));
	}

	@Test
	void testGetAccessRequestConfirmationUrl() {
		assertThat(apiSupport.getAccessRequestConfirmationUrl(REQUEST_ID),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.ACCESS_REQUEST_PAGE + '/' + REQUEST_ID + ApiSupport.CONFIRM_POSTFIX));
	}

	@Test
	void testGetAccessRequestOnboardingUrl() {
		assertThat(apiSupport.getAccessRequestOnboardingUrl(REQUEST_ID),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.ACCESS_REQUEST_PAGE + '/' + REQUEST_ID + ApiSupport.ONBOARD_POSTFIX));
	}

	@Test
	void testGetAccessRequestAbortUrl() {
		assertThat(apiSupport.getAccessRequestAbortUrl(REQUEST_ID),
				is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.ACCESS_REQUEST_PAGE + '/' + REQUEST_ID + ApiSupport.ABORT_POSTFIX));
	}

	@Test
	void testGetAccessRequestInitiateApi() {
		assertThat(apiSupport.getAccessRequestInitiateApi(REQUEST_ID),
				is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.ACCESS_REQUEST_INITIATE + '/' + REQUEST_ID));
	}

	@Test
	void testGetAccessRequestCompleteApi() {
		assertThat(apiSupport.getAccessRequestCompleteApi(REQUEST_ID),
				is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.ACCESS_REQUEST_COMPLETE + '/' + REQUEST_ID));
	}

	@ParameterizedTest
	@CsvSource(value = { "''", "null" }, nullValues = "null")
	void testGetAccessRequestCompleteApiWithAccessRequestBase(String baseUrl) {
		setupApi(baseUrl, PERIMETER_URL, OIDC_PERIMETER_URL);
		assertThat(apiSupport.getAccessRequestCompleteApi(REQUEST_ID),
				is(PERIMETER_URL + ApiSupport.API_CONTEXT + ApiSupport.ACCESS_REQUEST_COMPLETE + '/' + REQUEST_ID));
	}

	@Test
	void testGetAccessRequestAbortApi() {
		assertThat(apiSupport.getAccessRequestAbortApi(REQUEST_ID),
				is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.ACCESS_REQUEST_ABORT + '/' + REQUEST_ID));
	}

	@Test
	void testGetHrdCpApi() {
		assertThat(apiSupport.getHrdCpApi(ISSUER_1_ID, REQUEST_ID),
				is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.HRD_CP_API + '/' + ISSUER_1_ENCODED + '?' +
						ApiSupport.HRD_ID_PARAM + '=' + REQUEST_ID));
	}

	@Test
	void testGetHrdRpApi() {
		assertThat(apiSupport.getHrdRpApi(ISSUER_1_ID, REQUEST_ID), is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.HRD_RP_API +
				'/' + ISSUER_1_ENCODED + ApiSupport.HRD_TILES_POSTFIX + '?' + ApiSupport.HRD_ID_PARAM + '=' + REQUEST_ID));
	}

	@Test
	void testGetSsoRpApi() {
		assertThat(apiSupport.getSsoRpApi(ISSUER_1_ID), is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.SSO_RP_API +
				'/' + ISSUER_1_ENCODED));
	}

	@Test
	void testGetSsoGroupApi() {
		assertThat(apiSupport.getSsoGroupApi(GROUP_NAME, ISSUER_1_ID, ISSUER_2_ID, SUBJECT_NAME_ID),
				is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.SSO_GROUP_API + '/' + GROUP_NAME + '/' +
						ISSUER_1_ENCODED + '/' + ISSUER_2_ENCODED + '/' + SUBJECT_NAME_ID_ENCODED));
	}

	@Test
	void testGetSsoAllParticipantsApi() {
		assertThat(apiSupport.getSsoParticipantsApi(), is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.SSO_PARTICIPANTS_API));
	}

	@Test
	void testGetSsoParticipantsApi() {
		assertThat(apiSupport.getSsoParticipantsApi(GROUP_NAME),
				is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.SSO_PARTICIPANTS_API + '/' + GROUP_NAME));
	}

	@Test
	void testGetDeviceInfoApi() {
		assertThat(apiSupport.getDeviceInfoApi(), is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.DEVICE_INFO_API));
	}

	@Test
	void testContextNotDuplicated() {
		setupApi(BASE_URL + ApiSupport.FRONTEND_CONTEXT, PERIMETER_URL, OIDC_PERIMETER_URL);
		assertThat(apiSupport.getSsoUrl(), is(BASE_URL + ApiSupport.FRONTEND_CONTEXT + ApiSupport.SSO_PAGE));
	}

	@ParameterizedTest
	@MethodSource
	void testRemovePrefix(String baseUrl, String url, String relative) {
		setupApi(baseUrl, PERIMETER_URL, OIDC_PERIMETER_URL);
		assertThat(apiSupport.relativeUrl(url), is(relative));
	}

	static String[][] testRemovePrefix() {
		return new String[][] {
				{ null, null, null },
				{ BASE_URL, null, null },
				{ BASE_URL, BASE_URL + ApiSupport.API_CONTEXT + "/sub/url?query", "/sub/url?query" },
				// context only removed once:
				{ BASE_URL + ApiSupport.FRONTEND_CONTEXT, BASE_URL + ApiSupport.FRONTEND_CONTEXT +
						ApiSupport.FRONTEND_CONTEXT + "/subpath", ApiSupport.FRONTEND_CONTEXT + "/subpath" },
				{ BASE_URL, BASE_URL + ApiSupport.FRONTEND_CONTEXT + "/failure/123", "/failure/123" },
				{ BASE_URL, PERIMETER_URL + ApiSupport.FRONTEND_CONTEXT + "/ar/1", "/ar/1" },
				{ BASE_URL, BASE_URL + "/profile/2", BASE_URL + "/profile/2" },
				{ BASE_URL, PERIMETER_URL + "/ar/1", PERIMETER_URL + "/ar/1" },
				{ BASE_URL, "https://localhost:9999/any", "https://localhost:9999/any" }
		};
	}

	@Test
	void testGetSkinnyHrd() {
		var result = apiSupport.getSkinnyHrd("ct=content1", "rq=request1", "/skinny");
		assertThat(result, is(BASE_URL + "/skinny?rq=request1&ct=content1&" + VERSION_INFO ));
	}

	@Test
	void testGetProfiles() {
		var result = apiSupport.getProfilesApi();
		assertThat(result, is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.PROFILES_API));
	}

	@Test
	void testSelectProfile() {
		var result = apiSupport.getProfileApi();
		assertThat(result, is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.PROFILE_API));
	}

	@Test
	void testContinueToHrd() {
		var sessionId = "authnReq12";
		var result = apiSupport.getContinueToHrdApi(sessionId);
		assertThat(result, is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.HRD_API +
						'/' + ApiSupport.encodeUrlParameter(sessionId) + ApiSupport.CONTINUE_POSTFIX));
	}

	@Test
	void testSupportInfo() {
		var sessionId = "authnReq12";
		var errorCode = "unknown_error";
		var result = apiSupport.getSupportInfoApi(errorCode, sessionId);
		assertThat(result, is(BASE_URL + ApiSupport.API_CONTEXT + ApiSupport.SUPPORT_API +
						'/' + errorCode + '/' + ApiSupport.encodeUrlParameter(sessionId)));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,false",
			"/,false",
			ApiSupport.FRONTEND_CONTEXT + ",false",
			ApiSupport.API_CONTEXT + ",true",
			ApiSupport.API_CONTEXT + "/foo,true"
	}, nullValues = "null")
	void testIsApiPath(String path, boolean expected) {
		assertThat(ApiSupport.isApiPath(path), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,false",
			"/,false",
			ApiSupport.API_CONTEXT + ",false",
			ApiSupport.FRONTEND_CONTEXT + ",true",
			"/skinnyColHRD.html,true",
			ApiSupport.FRONTEND_CONTEXT + "/bar" + ",true"
	}, nullValues = "null")
	void testIsFrontendPath(String path, boolean expected) {
		assertThat(ApiSupport.isFrontendPath(path), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,false",
			"/,false",
			ApiSupport.FRONTEND_CONTEXT + ",false",
			ApiSupport.API_CONTEXT + ",true",
			ApiSupport.ADFS_ENTRY_URL + ",true",
			ApiSupport.XTB_LEGACY_ENTRY_URL + ",true"
	}, nullValues = "null")
	void testIsSamlPath(String path, boolean expected) {
		assertThat(ApiSupport.isSamlPath(path), is(expected));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"null,false",
			"http://%%localhost,false",
			"http://testuser:dummy@localhost:4200,false",
			"http://user@localhost:4200,false",
			OIDC_PERIMETER_URL + ",true",
			OIDC_PERIMETER_URL + "/test,true",
			BASE_URL + ",true",
			BASE_URL + "/path?a=b,true",
			PERIMETER_URL + ",true",
			PERIMETER_URL + "?param1=v1&param2=v2,true",
			"https://client.trustbroker.swiss,false"
	}, nullValues = "null")
	void testIsInternalUrl(String url, boolean expected) {
		assertThat(apiSupport.isInternalUrl(url), is(expected));
	}

}
