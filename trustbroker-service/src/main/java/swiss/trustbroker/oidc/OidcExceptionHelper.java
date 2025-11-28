/*
 * Derivative work of original class from org.springframework.security:spring-security-oauth2-authorization-server:1.2.4:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationProvider
 *
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package swiss.trustbroker.oidc;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationConsentAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.oidc.tx.FragmentUtil;
import swiss.trustbroker.saml.util.SamlStatusCode;
import swiss.trustbroker.util.ApiSupport;

/**
 * Small parts copied from spring-security-oauth2-authorization-server:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationValidator
 * Javadoc of original class:
 *
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Authorization Request
 * used in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 0.1.2
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationValidator
 * @see OAuth2AuthorizationCodeAuthenticationProvider
 * @see OAuth2AuthorizationConsentAuthenticationProvider
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1">Section 4.1.1 Authorization Request</a>
 */
@Slf4j
@SuppressWarnings("javaarchitecture:S7091")
public class OidcExceptionHelper {

	// own class is just for this class marking that the description is OK for use as error_description
	static class OidcAuthenticationException extends OAuth2AuthenticationException {
		OidcAuthenticationException(OAuth2Error error, String message) {
			super(error, message);
		}
	}

	private static final String SPRING_ERROR_PAGE = ApiSupport.ERROR_PAGE_URL + "?error";

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

	// Spring authentication server error patterns

	static final String OAUTH_2_0_PARAMETER = "OAuth 2.0 Parameter: ";

	static final String CLIENT_AUTH_FAILED = "Client authentication failed: ";

	static final String DEFAULT_ERROR_CODE = "access_denied";

	public static final String ERROR_URI_PARAM = "error_uri";

	public static final String ERROR_DESCRIPTION_PARAM = "error_description";

	private OidcExceptionHelper() {
	}

	public static String buildLocationForAuthenticationException(
			HttpServletRequest request, String errorUri, String errorBaseUri, String handler, Predicate<String> urlValidator) {
		var authException = (AuthenticationException) request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
		var session = request.getSession(false);
		if (authException == null && session != null) {
			authException = (AuthenticationException) session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
		}
		return buildLocationForAuthenticationException(request, authException, errorUri, errorBaseUri, handler, urlValidator);
	}

	public static String buildLocationForAuthenticationException(HttpServletRequest request,
			AuthenticationException authException, String errorUri, String errorBaseUri, String handler,
			Predicate<String> urlValidator) {
		var clientId = OidcSessionSupport.getOidcClientId(request, null);
		if (authException == null) {
			log.info("Missing OIDC exception - redirect to OIDC clientId={} not possible", clientId);
			return null;
		}
		// validation failure through throwError of this class or OAuth2AuthorizationCodeRequestAuthenticationProvider
		if (authException instanceof OAuth2AuthorizationCodeRequestAuthenticationException codeException) {
			var authenticationToken = codeException.getAuthorizationCodeRequestAuthentication();
			if (authenticationToken != null && authenticationToken.getRedirectUri() == null) {
				log.info("Missing OIDC exception parameter {}/{} - redirect to OIDC wire clientId={} redirectUri={} denied ({})"
						+ ". HINT: Check that redirect_uri is configured and validator works properly.",
						OAuth2ParameterNames.CLIENT_ID,
						OAuth2ParameterNames.REDIRECT_URI,
						clientId, StringUtil.clean(request.getParameter(OidcUtil.REDIRECT_URI)), handler);
				return null;
			}
		}
		String errorCode = null;
		String description = null;
		if (authException instanceof OidcAuthenticationException oidcException) {
			var error = oidcException.getError(); // never null
			errorCode = error.getErrorCode();
			description = error.getDescription(); // use XTB description
		}
		else if (authException instanceof OAuth2AuthenticationException oidcException) {
			var error = oidcException.getError(); // never null
			errorCode = error.getErrorCode();
			description = mapCodeToDescription(errorCode, error.getDescription(), oidcException.getMessage());
		}
		else if (authException instanceof Saml2AuthenticationException samlException) {
			var error = samlException.getSaml2Error(); // never null
			errorCode = error.getErrorCode();
			description = mapCodeToDescription(errorCode, error.getDescription(), samlException.getMessage());
		}
		if (errorCode == null) {
			// we need at least an error code for the response
			log.info("Missing OIDC exception errorCode in exception={} of class={} - redirect to OIDC clientId={} aborted ({})",
					authException.getMessage(), authException.getClass().getName(), clientId, handler);
			return null;
		}
		var redirectUri = getRedirectUrl(request, errorCode, description, errorUri, errorBaseUri, urlValidator);
		log.debug("OIDC exception for clientId={} errorCode={}  redirectTo={}, errorDescription='{}' ({})",
				clientId, errorCode, redirectUri, description, handler);
		return redirectUri;
	}

	private static String getRedirectUriFromSession(HttpServletRequest request) {
		var redirectUri = OidcSessionSupport.getInitialRedirectUri(request.getSession(false));
		if (redirectUri == null) {
			log.debug("No {} in session, no redirecting to relying party", OidcUtil.REDIRECT_URI);
		}
		return redirectUri;
	}

	private static String getRedirectUrl(HttpServletRequest request, String errorCode, String description, String errorUri,
			String errorBaseUri, Predicate<String> urlValidator) {
		// from session
		var redirectUri = getRedirectUriFromSession(request);
		// from request because there was no session
		if (redirectUri == null) {
			redirectUri = OidcUtil.getRedirectUriFromRequest(request);
		}
		if (redirectUri == null) {
			return null; // direct response handling
		}
		// only allow redirect to validated URI
		if (!urlValidator.test(redirectUri)) {
			log.error("Blocking unsupported redirectUrl={}", redirectUri);
			return null;
		}
		// construct redirect with error details
		try {
			var state = OidcSessionSupport.getInitialClientState(request);
			return getOidcErrorLocation(redirectUri, errorCode, description, errorUri, errorBaseUri, state);
		}
		catch (IllegalArgumentException ex) {
			log.error("Could not parse redirectUrl={} message=\"{}\"", redirectUri, ex.getMessage());
			return null;
		}
	}

	public static String getOidcErrorLocation(String baseUri, String errorCode, String description, String errorUri,
			String errorBaseUri, String state) {
		baseUri = FragmentUtil.discardAllErrorsInRedirect(baseUri); // client looping our own error
		var builder = UriComponentsBuilder.fromUriString(baseUri);
		builder.queryParam(OidcUtil.OIDC_ERROR, errorCode);
		if (StringUtils.hasLength(state)) {
			builder.queryParam(OidcUtil.OIDC_STATE_ID, WebUtil.urlEncodeValue(state));
		}
		if (StringUtils.hasLength(description)) {
			builder.queryParam(ERROR_DESCRIPTION_PARAM, WebUtil.urlEncodeValue(description));
		}
		if (StringUtils.hasLength(errorUri)) {
			var absoluteUri = WebUtil.getAbsoluteUrl(errorBaseUri, errorUri);
			builder.queryParam(ERROR_URI_PARAM, WebUtil.urlEncodeValue(absoluteUri));
		}
		// leave out error_description created by Spring Authorization Server, it is technical
		return builder.build().toUriString();
	}

	// store exception in request transfer it to the ErrorViewResolver
	public static void saveAuthenticationException(HttpServletRequest request, AuthenticationException authException) {
		request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, authException);
	}

	// only checks request (set by XTB), not session (set by Spring)
	public static boolean hasAuthenticationException(HttpServletRequest request) {
		return request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION) != null;
	}

	// copied from OAuth2AuthorizationCodeRequestAuthenticationProvider
	public static void throwError(String errorCode, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient) {
		OAuth2Error error = new OAuth2Error(errorCode, OAUTH_2_0_PARAMETER + parameterName, ERROR_URI);
		throwError(error, parameterName, authorizationCodeRequestAuthentication, registeredClient);
	}

	public static void throwError(OAuth2Error error, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient) {
		throw createOidcException(error, parameterName, authorizationCodeRequestAuthentication, registeredClient);
	}

	static OAuth2AuthorizationCodeRequestAuthenticationException createOidcException(OAuth2Error error, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken oauth2Token,
			RegisteredClient registeredClient) {
		var redirectUri = oauth2Token.getRedirectUri();
		if (!StringUtils.hasText(oauth2Token.getRedirectUri())) {
			if (registeredClient.getRedirectUris().isEmpty()) {
				log.error("RegisteredClient clientId={} has no redirectUris", registeredClient.getClientId());
			}
			else {
				redirectUri = registeredClient.getRedirectUris().iterator().next();
			}
		}
		if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST) &&
				parameterName.equals(OAuth2ParameterNames.REDIRECT_URI)) {
			redirectUri = null;        // Prevent redirects
		}

		var result = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				oauth2Token.getAuthorizationUri(),
				oauth2Token.getClientId(),
				(Authentication) oauth2Token.getPrincipal(), redirectUri,
				oauth2Token.getState(), oauth2Token.getScopes(),
				oauth2Token.getAdditionalParameters());
		result.setAuthenticated(true);
		return new OAuth2AuthorizationCodeRequestAuthenticationException(error, result);
	}

	public static List<Saml2Error> enrichResponseError(OidcProperties oidcProperties, Response response,
			Collection<Saml2Error> errors) {
		var statusCode = OpenSamlUtil.getStatusCode(response);
		// OpenSaml4AuthenticationProvider only provides the status code, add an enriched error
		var statusMessage = OpenSamlUtil.getStatusMessage(response);
		var nestedStatusCode = OpenSamlUtil.getNestedStatusCode(response);
		var errorMessage = String.format("statusCode=%s nestedStatusCode=%s message=\"%s\"",
				statusCode, nestedStatusCode, statusMessage);
		var mappedCode = mapErrorCode(oidcProperties, statusCode, nestedStatusCode, statusMessage, errors);
		var code = WebUtil.urlEncodeValue(mappedCode);
		List<Saml2Error> resultErrors = new ArrayList<>();
		// errors extracted by OpenSaml4AuthenticationProvider, OIDC client gets only first one
		// we attach the mapped code at the beginning, so it is used
		resultErrors.add(new Saml2Error(code, errorMessage));
		resultErrors.addAll(errors);
		log.error("Validation of SAML responseId={} inResponseTo={} failed for clientId={} with errors={}",
				response.getID(), response.getInResponseTo(), OidcSessionSupport.getOidcClientId(), resultErrors);
		return resultErrors;
	}

	static String mapErrorCode(OidcProperties oidcProperties, String statusCode, String nestedStatusCode, String statusMessage,
			Collection<Saml2Error> errors) {
		var authServerErrorCode = getAuthServerErrorCode(errors);
		var mappedStatusCode = SamlStatusCode.toOidcErrorCode(
				oidcProperties, statusCode, nestedStatusCode, statusMessage, authServerErrorCode);
		if (mappedStatusCode != null) {
			log.debug("Using mapped oidcCode={}", mappedStatusCode);
			return mappedStatusCode;
		}
		if (authServerErrorCode != null) {
			// this is what would be used without mapping
			log.debug("Using first error from auth server error list oidcCode={} ", authServerErrorCode);
			return authServerErrorCode;
		}
		var defaultCode = (oidcProperties != null) && StringUtils.hasLength(oidcProperties.getDefaultErrorCode()) ?
				oidcProperties.getDefaultErrorCode() : DEFAULT_ERROR_CODE;
		log.debug("Use default oidcCode={}", defaultCode);
		return defaultCode;
	}

	private static String getAuthServerErrorCode(Collection<Saml2Error> errors) {
		var errorOpt = errors.stream().findFirst();
		if (errorOpt.isPresent()) {
			var error = errorOpt.get();
			// forward Spring authorization server error
			// Description "Invalid status []" contains the full status code URN (equal to statusCode)
			if (error.getDescription() == null || !error.getDescription().startsWith("Invalid status [")) {
				log.debug("Use oidcCode={} from Saml2Error error list with description=\"{}\"",
						error.getErrorCode(), error.getDescription());
				return error.getErrorCode();
			}
		}
		return null;
	}

	public static boolean isSpringErrorPage(String location) {
		return location != null && (location.contains(SPRING_ERROR_PAGE) || location.contains(ApiSupport.ERROR_PAGE_URL));
	}

	public static OAuth2AuthenticationException createOidcException(String errorCode, String message, String description) {
		var error = new OAuth2Error(errorCode, description, null);
		return new OidcAuthenticationException(error, message);
	}

	private static String mapCodeToDescription(String errorCode, String description, String message) {
		var result = mapMessage(message);
		if (result == null) {
			result = mapMessage(description);
		}
		log.debug("Mapped errorCode={}, description={}, message={} to result={}", errorCode, description, message, result);
		return result;
	}

	private static String mapMessage(String message) {
		if (message == null) {
			return null;
		}
		if (message.startsWith(OAUTH_2_0_PARAMETER)) {
			// extract name of faulty parameter
			return message.substring(OAUTH_2_0_PARAMETER.length());
		}
		if (message.startsWith(CLIENT_AUTH_FAILED)) {
			// extract name of faulty parameter
			return message.substring(CLIENT_AUTH_FAILED.length());
		}
		return null;
	}

}
