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

import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;
import swiss.trustbroker.common.saml.util.Base64Util;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.homerealmdiscovery.controller.HrdController;

/**
 * Build application and API URLs in a consistent way with properly encoded parameters.
 * <p>
 * Note: Only the URLs needed from business or test code have been added.
 */
@Component
@SuppressWarnings("java:S1075")
public class ApiSupport {

	/**
	 * Base URL of Angular application, prefix for the following page paths.
	 * See Angular app-routing module for URL mappings and their parameters.
	 */
	public static final String FRONTEND_CONTEXT = "/app";

	static final String ERROR_PAGE = "/failure";

	public static final String ERROR_PAGE_URL = FRONTEND_CONTEXT + ERROR_PAGE;

	public static final String HRD_PAGE = "/home";

	static final String DEVICE_INFO_PAGE = "/device";

	static final String PROFILE_SELECTION_PAGE = "/profile/selection";

	static final String SSO_PAGE = "/sso";

	public static final String ANNOUNCEMENTS_PAGE = "/announcements";

	static final String ACCESS_REQUEST_PAGE = "/accessrequest";

	/**
	 * Base URL of APIs, prefix for the following API paths.
	 * See controllers for URL mappings and their parameters.
	 *
	 * @see HrdController
	 * @see swiss.trustbroker.saml.controller.AppController
	 * @see swiss.trustbroker.sso.controller.SsoController
	 */
	public static final String API_CONTEXT = "/api/v1";

	static final String HRD_API = "/hrd";

	static final String HRD_RP_API = HRD_API + "/relyingparties";

	static final String HRD_TILES_POSTFIX = "/tiles";

	static final String CONTINUE_POSTFIX = "/continue";

	static final String PROGRESS_POSTFIX = "/progress";

	static final String CONFIRM_POSTFIX = "/confirm";

	static final String ONBOARD_POSTFIX = "/onboard";

	static final String ABORT_POSTFIX = "/abort";

	static final String INITIATE_POSTFIX = "/initiate";

	static final String HRD_CP_API = HRD_API + "/claimsproviders";

	static final String HRD_ID_PARAM = "session";

	static final String SSO_GROUP_API = "/sso/group";

	static final String SSO_RP_API = "/sso/rp";

	static final String SSO_PARTICIPANTS_API = "/sso/participants";

	static final String DEVICE_INFO_API = "/device/info";

	static final String ACCESS_REQUEST_COMPLETE = "/accessrequest/complete";

	static final String ACCESS_REQUEST_INITIATE = "/accessrequest/initiate";

	static final String ACCESS_REQUEST_ABORT = "/accessrequest/abort";

	static final String ACCESS_REQUEST_TRIGGER = "/accessrequest/trigger";

	private static final String MONITORING_ACS_API = "/monitoring/relyingparties";

	public static final String MONITORING_ACS_URL = API_CONTEXT + MONITORING_ACS_API;

	public static final String CONFIG_STATUS_API = API_CONTEXT + "/config/status";

	public static final String CONFIG_SCHEMAS_API = API_CONTEXT + "/config/schemas";

	public static final String VERSION_API = API_CONTEXT + "/version";

	public static final String CONFIG_API = API_CONTEXT + "/config";

	public static final String CONFIG_FRONTEND_API = CONFIG_API + "/frontend";

	static final String PROFILES_API = HRD_API + "/profiles";

	static final String PROFILE_API = HRD_API + "/profile";

	public static final String SAML_API = API_CONTEXT + "/saml";

	public static final String WSTRUST_API = API_CONTEXT + "/wstrust";

	public static final String ARP_API = "/saml/arp";

	static final String METADATA_API = "/metadata";

	public static final String METADATA_URL = API_CONTEXT + METADATA_API; // legacy

	public static final String SAML_METADATA_URL = SAML_API + METADATA_API;

	public static final String ARP_URL = API_CONTEXT + ARP_API;

	public static final String RECONFIG_URL = API_CONTEXT + "/config";

	static final String SUPPORT_API = "/support";

	static final String ASSETS_API = HRD_API + "/assets";

	public static final String ASSETS_URL = API_CONTEXT + ASSETS_API;

	/**
	 * OIDC support
	 */
	public static final String XTB_OIDC_CONFIG_PATH = "/api/v1/openid-configuration";

	public static final String PUBLIC_OIDC_CONFIG_PATH = "/.well-known/openid-configuration";

	public static final String KEYCLOAK_REALMS = "/realms";

	public static final String SPRING_OAUTH2 = "/oauth2";

	public static final String KEYCLOAK_AUTH = "/auth";

	public static final String KEYCLOAK_CERTS = "/certs";

	public static final String OIDC_AUTH = "/authorize";

	public static final String OIDC_TOKEN = "/token";

	public static final String OIDC_USERINFO = "/userinfo";

	public static final String OIDC_KEYS = "/jwks";

	public static final String OIDC_INTROSPECT = "/introspect";

	public static final String OIDC_REVOKE = "/revoke";

	public static final String OIDC_LOGOUT = "/logout";

	public static final String OIDC_CHECK_3PCOOKIE = "/3p-cookies/step1";

	public static final String PROTOCOL_OPENIDCONNECT = "/protocol/openid-connect";

	public static final String SPRING_OAUTH2_AUTHORIZE_CTXPATH = SPRING_OAUTH2 + OIDC_AUTH;

	public static final String SPRING_SAML_LOGIN_CTXPATH = "/login";

	public static final String SPRING_SAML_FEDERATION_CTXPATH = "/login/saml2/sso/";

	public static final String SPRING_SAML_AUTHENTICATE_CTXPATH = "/saml2/authenticate/";

	public static final String OIDC_API = "/oidc";

	public static final String OIDC_RESPONSE_API = OIDC_API + "/response";

	public static final String OIDC_RESPONSE_URL = API_CONTEXT + OIDC_RESPONSE_API;

	public static final String ADFS_PATH = "/adfs";

	public static final String ADFS_ENTRY_PATH = "/ls";

	public static final String ADFS_ENTRY_URL = ADFS_PATH + ADFS_ENTRY_PATH;

	public static final String ADFS_ENTRY_URL_TRAILING_SLASH = ADFS_ENTRY_URL + "/";

	public static final String ADFS_WS_TRUST_ENTRY_URL = ADFS_PATH + "/services/trust";

	public static final String ADFS_WS_TRUST_COMPAT_PATH = "/13/issuedtokenmixedsymmetricbasic256";

	public static final String ADFS_WS_TRUST_COMPAT_URL = ADFS_WS_TRUST_ENTRY_URL + ADFS_WS_TRUST_COMPAT_PATH;

	public static final String XTB_LEGACY_ADFS_PATH = "/trustbroker" + ADFS_PATH; // deprecated

	public static final String XTB_LEGACY_ENTRY_URL = XTB_LEGACY_ADFS_PATH + ADFS_ENTRY_PATH; // deprecated

	public static final String XTB_ALTERNATE_METADATA_ENDPOINT = "/FederationMetadata/2007-06/FederationMetadata.xml";

	public static final String XTB_LOWER_CASE_ALTERNATE_METADATA_ENDPOINT =
			"/federationmetadata/2007-06/federationmetadata.xml"; // must be constant

	public static final String SKINNY_PATH= "/skinny";

	private final TrustBrokerProperties trustBrokerProperties;

	public ApiSupport(TrustBrokerProperties trustBrokerProperties) {
		this.trustBrokerProperties = trustBrokerProperties;
	}

	public static boolean isApiPath(String path) {
		return path != null && path.startsWith(API_CONTEXT);
	}

	public static boolean isSamlPath(String path) {
		return path !=null && (isApiPath(path) || path.startsWith(ADFS_PATH) || path.startsWith(XTB_LEGACY_ADFS_PATH));
	}

	public static boolean isFrontendPath(String path) {
		return path != null && (path.startsWith(FRONTEND_CONTEXT) || path.startsWith(SKINNY_PATH));
	}

	public static boolean isKeyloakRealmsPath(String path) {
		return path != null && path.startsWith(ApiSupport.KEYCLOAK_REALMS);
	}

	public static boolean isOidcSubSystemPath(String path) {
		return path != null && path.startsWith(ApiSupport.SPRING_OAUTH2);
	}

	public static boolean isOidcAuthPath(String path) {
		return path != null && (path.endsWith(ApiSupport.OIDC_AUTH) || path.endsWith(KEYCLOAK_AUTH));
	}

	private static boolean isOidcUserInfoPath(String path) {
		return path != null && path.endsWith(ApiSupport.OIDC_USERINFO);
	}

	private static boolean isOidcLogoutPath(String path) {
		return path != null && path.endsWith(ApiSupport.OIDC_LOGOUT);
	}

	public static boolean isSpringFederationPath(String path) {
		return path != null && (path.startsWith(ApiSupport.SPRING_SAML_LOGIN_CTXPATH)
				|| path.startsWith(ApiSupport.SPRING_SAML_AUTHENTICATE_CTXPATH));
	}

	public static boolean isOidcSessionPath(String path) {
		// We could use OidcSessionSupport.getOidcClientId here for consistency with
		// the session detection in the session management, but it's too heavy...
		// Keep in sync with OidcSecurityConfiguration.
		return isOidcSubSystemPath(path)
				|| isSpringFederationPath(path)
				|| isKeyloakRealmsPath(path)
				|| isOidcUserInfoPath(path)
				|| isOidcLogoutPath(path)
				|| isOidcConfigPath(path); // actually no session needed but CORS may be
	}

	public static boolean isOidcConfigPath(String path) {
		return path != null && (path.endsWith(ApiSupport.PUBLIC_OIDC_CONFIG_PATH)
				|| path.equals(ApiSupport.XTB_OIDC_CONFIG_PATH));
	}

	public static boolean isUserInfoRequest(String path) {
		return path != null && path.endsWith(ApiSupport.OIDC_USERINFO);
	}

	public static boolean isLogoutRequest(String path) {
		return path != null && path.endsWith(ApiSupport.OIDC_LOGOUT);
	}

	public static boolean isOidcCheck3pCookie(String path) {
		return path != null && path.contains(ApiSupport.OIDC_CHECK_3PCOOKIE);
	}

	public String getHrdUrl(String issuer, String requestId) {
		return getFrontendUrl(FRONTEND_CONTEXT, HRD_PAGE, encodeUrlParameter(issuer), requestId);
	}

	public String getSkinnyHrd(String pageContent, String requestId, String skinnyHtml) {
		var frontendBaseUrl = trustBrokerProperties.getFrontendBaseUrl();
		// Prevent null in the url
		String versionInfo = trustBrokerProperties.getVersionInfo() != null ? trustBrokerProperties.getVersionInfo() : "NONE";
		var url = new StringBuilder();

		if (frontendBaseUrl != null) {
			url.append(frontendBaseUrl);
		}
		url.append(skinnyHtml);
		url.append("?");
		url.append(requestId);
		url.append("&");
		url.append(pageContent);
		url.append("&");
		url.append(versionInfo);
		return url.toString();
	}

	public String getDeviceInfoUrl(String cpIssuer, String rpIssuer, String requestId) {
		return getFrontendUrl(FRONTEND_CONTEXT, DEVICE_INFO_PAGE, encodeUrlParameter(cpIssuer),
				encodeUrlParameter(rpIssuer), requestId);
	}

	public String getProfileSelectionUrl(String stateID) {
		return getFrontendUrl(FRONTEND_CONTEXT, PROFILE_SELECTION_PAGE, stateID);
	}

	public String getErrorPageUrl() {
		return getFrontendUrl(FRONTEND_CONTEXT, ERROR_PAGE);
	}

	public String getErrorPageUrl(String errorType, String traceId) {
		if (traceId == null) {
			return getFrontendUrl(FRONTEND_CONTEXT, ERROR_PAGE, errorType);
		}
		return getFrontendUrl(FRONTEND_CONTEXT, ERROR_PAGE, errorType, traceId);
	}

	public String getErrorPageUrlWithFlags(String errorType, String traceId, String sessionId, List<String> flags) {
		var flagString = String.join("_", flags);
		return getFrontendUrl(FRONTEND_CONTEXT, ERROR_PAGE, errorType, traceId, encodeUrlParameter(sessionId), flagString);
	}

	public String getSsoUrl() {
		return getFrontendUrl(FRONTEND_CONTEXT, SSO_PAGE);
	}

	public String getSsoUrl(String group) {
		return getFrontendUrl(FRONTEND_CONTEXT, SSO_PAGE, group);
	}

	public String getAnnouncementsUrl(String issuer, String requestId, String appName) {
		return getFrontendUrl(FRONTEND_CONTEXT, ANNOUNCEMENTS_PAGE, encodeUrlParameter(issuer), requestId,
				encodeUrlParameter(appName));
	}

	public String getAccessRequestInitiateUrl(String sessionId) {
		return getFrontendUrl(FRONTEND_CONTEXT, ACCESS_REQUEST_PAGE, sessionId, INITIATE_POSTFIX);
	}

	public String getAccessRequestInProgressUrl(String sessionId) {
		return getFrontendUrl(FRONTEND_CONTEXT, ACCESS_REQUEST_PAGE, sessionId, PROGRESS_POSTFIX);
	}

	public String getAccessRequestOnboardingUrl(String sessionId) {
		return getFrontendUrl(FRONTEND_CONTEXT, ACCESS_REQUEST_PAGE, sessionId, ONBOARD_POSTFIX);
	}

	public String getAccessRequestAbortUrl(String sessionId) {
		return getFrontendUrl(FRONTEND_CONTEXT, ACCESS_REQUEST_PAGE, sessionId, ABORT_POSTFIX);
	}

	public String getAccessRequestConfirmationUrl(String sessionId) {
		return getFrontendUrl(FRONTEND_CONTEXT, ACCESS_REQUEST_PAGE, sessionId, CONFIRM_POSTFIX);
	}

	public String getAccessRequestCompleteApi(String requestId) {
		var baseUrl = getBaseUrl();
		return getFrontendUrlWithBase(baseUrl, API_CONTEXT, ACCESS_REQUEST_COMPLETE, requestId);
	}

	public String getAccessRequestInitiateApi(String requestId) {
		return getFrontendUrl(API_CONTEXT, ACCESS_REQUEST_INITIATE, requestId);
	}

	public String getAccessRequestTriggerApi(String application, String returnUrl) {
		var url = getFrontendUrl(API_CONTEXT, ACCESS_REQUEST_TRIGGER);
		url += "?appl=" + application;
		if (returnUrl != null) {
			url += "&returnURL=" + WebUtil.urlEncodeValue(returnUrl);
		}
		return url;
	}

	public String getAccessRequestAbortApi(String requestId) {
		return getFrontendUrl(API_CONTEXT, ACCESS_REQUEST_ABORT, requestId);
	}

	public String getSsoParticipantsApi() {
		return getFrontendUrl(API_CONTEXT, SSO_PARTICIPANTS_API);
	}

	public String getSsoParticipantsApi(String group) {
		return getFrontendUrl(API_CONTEXT, SSO_PARTICIPANTS_API, group);
	}

	public String getSsoGroupApi(String groupName, String rpIssuerId, String cpIssuerId, String subjectNameId) {
		return getFrontendUrl(API_CONTEXT, SSO_GROUP_API, groupName, encodeUrlParameter(rpIssuerId),
				encodeUrlParameter(cpIssuerId), encodeUrlParameter(subjectNameId) );
	}

	public String getSsoRpApi(String rpId) {
		return getFrontendUrl(API_CONTEXT, SSO_RP_API, encodeUrlParameter(rpId));
	}

	public String getDeviceInfoApi() {
		return getFrontendUrl(API_CONTEXT, DEVICE_INFO_API);
	}

	public String getHrdRpApi(String issuer, String authnRequestId) {
		return getFrontendUrl(API_CONTEXT, HRD_RP_API, encodeUrlParameter(issuer)) + HRD_TILES_POSTFIX
				+ '?' + HRD_ID_PARAM + '=' + authnRequestId;
	}

	public String getHrdRpContinueApi(String sessionId) {
		return getFrontendUrl(API_CONTEXT, HRD_RP_API, encodeUrlParameter(sessionId)) + CONTINUE_POSTFIX;
	}

	public String getHrdCpApi(String issuer, String authnRequestId) {
		// API inconsistency with query parameter instead of path parameter
		return getFrontendUrl(API_CONTEXT, HRD_CP_API, encodeUrlParameter(issuer)) + '?' + HRD_ID_PARAM + '=' + authnRequestId;
	}

	public String getMonitoringAcsUrl() {
		return getFrontendUrl(API_CONTEXT, MONITORING_ACS_API);
	}

	public String getMonitoringAcsUrl(String rpIssuer) {
		return getFrontendUrl(API_CONTEXT, MONITORING_ACS_API, WebUtil.urlEncodeValue(rpIssuer));
	}

	public String getMonitoringAcsUrl(String rpIssuer, String cpIssuer) {
		return getFrontendUrl(API_CONTEXT, MONITORING_ACS_API,
				WebUtil.urlEncodeValue(rpIssuer), WebUtil.urlEncodeValue(cpIssuer));
	}

	public String getMonitoringAcsUrlWithQueryParameters(String rpIssuer, String cpIssuer) {
		return getFrontendUrl(API_CONTEXT, MONITORING_ACS_API) +
				"?rpId=" + WebUtil.urlEncodeValue(rpIssuer)
				+ "&cpId=" + WebUtil.urlEncodeValue(cpIssuer);
	}

	// GET to fetch profiles
	public String getProfilesApi() {
		return getFrontendUrl(API_CONTEXT, PROFILES_API);
	}

	// POST to submit selected profile
	public String getProfileApi() {
		return getFrontendUrl(API_CONTEXT, PROFILE_API);
	}

	public String getContinueToHrdApi(String sessionId) {
		return getFrontendUrl(API_CONTEXT, HRD_API,encodeUrlParameter(sessionId) + CONTINUE_POSTFIX);
	}

	public String getSupportInfoApi(String errorCode, String sessionId) {
		return getFrontendUrl(API_CONTEXT, SUPPORT_API, errorCode, encodeUrlParameter(sessionId));
	}

	// realm is from config, not encoded in output
	public String getOidcResponseApi(String realm) {
		var baseUrl = getBaseUrl();
		return getFrontendUrlWithBase(baseUrl, API_CONTEXT, OIDC_RESPONSE_API, realm);
	}

	public boolean isInternalUrl(String uriString) {
		var uri = WebUtil.getValidatedUri(uriString);
		if (uri == null) {
			return false; // null or invalid
		}
		if (uri.getUserInfo() != null) { // not used internally
			return false;
		}
		var uriBase = uri.getScheme() + "://" + uri.getAuthority();
		return uriBase.equals(trustBrokerProperties.getFrontendBaseUrl())
				|| uriBase.equals(trustBrokerProperties.getPerimeterUrl())
				|| uriBase.equals(trustBrokerProperties.getOidc().getPerimeterUrl());
	}

	private String getBaseUrl() {
		var baseUrl = trustBrokerProperties.getFrontendBaseUrl();
		if (StringUtils.isEmpty(baseUrl)) {
			baseUrl = trustBrokerProperties.getPerimeterUrl();
		}
		return baseUrl;
	}

	// encodedParams must be properly encoded for adding to the path of the URL
	public String getFrontendUrl(String contextPath, String basePath, String... encodedParams) {
		var frontendBaseUrl = trustBrokerProperties.getFrontendBaseUrl();
		return getFrontendUrlWithBase(frontendBaseUrl, contextPath, basePath, encodedParams);
	}

	// encodedParams must be properly encoded for adding to the path of the URL
	private static String getFrontendUrlWithBase(String frontendBaseUrl, String contextPath, String basePath,
			String... encodedParams) {
		var url = new StringBuilder();
		// null in some tests
		if (frontendBaseUrl != null) {
			url.append(frontendBaseUrl);
		}
		// transition: ensure we have the context once:
		if (frontendBaseUrl == null || !frontendBaseUrl.endsWith(contextPath)) {
			url.append(contextPath);
		}
		url.append(basePath);
		for (var param : encodedParams) {
			if (param != null) {
				if (!param.startsWith("/")) {
					url.append('/');
				}
				url.append(param);
			}
		}
		return url.toString();
	}

	public static String encodeUrlParameter(String value) {
		return Base64Util.urlEncode(value);
	}

	public static String decodeUrlParameter(String encodedValue) {
		return StringUtil.clean(Base64Util.urlDecode(encodedValue));
	}

	@SuppressWarnings("java:S4973") // checking String for not same object
	public String relativeUrl(String targetUrl) {
		if (targetUrl != null) {
			var result = removePrefix(targetUrl, trustBrokerProperties.getFrontendBaseUrl(), API_CONTEXT);
			if (result != targetUrl) {
				return result;
			}
			result = removePrefix(targetUrl, trustBrokerProperties.getFrontendBaseUrl(), FRONTEND_CONTEXT);
			if (result != targetUrl) {
				return result;
			}
			result = removePrefix(targetUrl, trustBrokerProperties.getPerimeterUrl(), FRONTEND_CONTEXT);
			if (result != targetUrl) {
				return result;
			}
		}
		return targetUrl;
	}

	// returns url (same object) if not removed
	private static String removePrefix(String url, String prefix, String context) {
		if (url == null) {
			return url;
		}
		if (prefix != null) {
			if (context != null && !prefix.endsWith(context)) {
				prefix += context;
			}
			if (url.startsWith(prefix)) {
				return url.substring(prefix.length());
			}
		}
		else if (context != null && url.startsWith(context)) {
			return url.substring(context.length());
		}
		return url;
	}

}
