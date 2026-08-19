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

package swiss.trustbroker.oidc;

import java.time.Instant;
import java.util.Date;
import java.util.Set;

import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.Audiences;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.CounterParty;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Resources;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;
import swiss.trustbroker.util.WebSupport;

@Slf4j
public class OidcValidator {

	private OidcValidator(){}

	private static final String JWT_TOKEN_TYPE_VALUE = "urn:ietf:params:oauth:token-type:jwt";

	public static void validateClaimsProviderMapping(RelyingParty relyingParty, ClaimsParty claimsParty, String errorUri) {
		var claimsProviderMappings = relyingParty.getClaimsProviderMappings();
		if (claimsProviderMappings == null) {
			var message = String.format("Missing ClaimsProviderMappings for RelyingParty=%s", relyingParty.getId());
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, message, errorUri);
			return;
		}
		var claimsProviderList = claimsProviderMappings.getClaimsProviderList();
		var rpCp = claimsProviderList.stream()
									 .filter(claimsProvider -> claimsProvider.getId().equals(claimsParty.getId()))
									 .findAny();
		if (rpCp.isEmpty()) {
			var message = String.format("Missing ClaimsProviderMapping for ClaimParty=%s in RelyingParty=%s", claimsParty.getId(), relyingParty.getId());
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, message, errorUri);
		}
	}

	public static void validateInputParams(OidcClient rpOidcClient, RegisteredClient registeredClient, String registeredClientId,
										   OAuth2TokenExchangeAuthenticationToken tokenExchangeAuthentication, String errorUri) {
		if (rpOidcClient == null || registeredClient == null) {
			var message = String.format("Missing OIDC client configuration for token exchange clientId=%s", registeredClientId);
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_REQUEST, message, errorUri);
			return;
		}

		if (log.isTraceEnabled()) {
			log.trace("Retrieved authorization with token for client {}", registeredClientId);
		}

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.TOKEN_EXCHANGE)) {
			var message = String.format("Missing authorization grant type for token exchange authentication clientId=%s", registeredClientId);
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_GRANT, message, errorUri);
		}

		if (JWT_TOKEN_TYPE_VALUE.equals(tokenExchangeAuthentication.getRequestedTokenType()) && !OAuth2TokenFormat.SELF_CONTAINED.equals(registeredClient.getTokenSettings().getAccessTokenFormat())) {
			CustomOAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_REQUEST, "requested_token_type", errorUri);
		}
	}

	static void validateRequestedAudiences(Set<String> audiences, OidcClient oidcClient, String errorUri) {
		Audiences configAudiences = oidcClient.getAudiences();

		var allowedAud = configAudiences != null ? configAudiences.getAudiencesList() : null;
		boolean noConfiguredAudiences = (allowedAud == null || allowedAud.isEmpty());
		boolean hasRequestedAudiences = (audiences != null && !audiences.isEmpty());

		if ((hasRequestedAudiences && noConfiguredAudiences) || (allowedAud != null && (audiences == null || !allowedAud.containsAll(audiences)))) {
			var message = String.format("Audiences=%s are not matching configured audience=%s", audiences, configAudiences);
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_REQUEST, message, errorUri);
		}
	}

	static void validateRequestResources(Set<String> resources, OidcClient oidcClient, String errorUri) {
		Resources configResources = oidcClient.getResources();

		var allowedResources = configResources != null ? configResources.getResourceList() : null;
		boolean noConfiguredResources = (allowedResources == null || allowedResources.isEmpty());
		boolean hasRequestedResources = (resources != null && !resources.isEmpty());
		Set<String> requested = (resources == null) ? Set.of() : resources;

		if ((hasRequestedResources && noConfiguredResources) || (allowedResources != null && (resources == null || !allowedResources.containsAll(requested)))) {
			var message = String.format("Resources=%s are not matching configured resources=%s", resources, configResources);
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_REQUEST, message, errorUri);
		}

		for (String resource : requested) {
			validateResourceUri(resource, errorUri);
		}
	}

	// The value of the resource parameter MUST be an absolute URI, as specified by Section 4.3 of [RFC3986],
	// that MAY include a query component and MUST NOT include a fragment component.
	static void validateResourceUri(String resource, String errorUri) {
		if (resource == null || resource.isEmpty()) {
			return;
		}

		var uri = WebUtil.getValidatedUri(resource);
		if (uri == null || uri.getScheme() == null || uri.getFragment() != null || uri.getAuthority() == null) {
			var message = String.format("Invalid resource url=%s", resource);
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_REQUEST, message, errorUri);
		}
	}

	public static void validateSubjectTokenIatExpNbf(JWTClaimsSet claimsSet, OidcClient oidcClient,
													 TrustBrokerProperties trustBrokerProperties, String errorUri) {
		var trustBrokerPropertiesSecurity = trustBrokerProperties.getSecurity();
		var tokenIat = claimsSet.getIssueTime();
		long now = Instant.now().toEpochMilli();
		var oidcSecurityPolicies = oidcClient.getOidcSecurityPolicies();
		validIat(oidcSecurityPolicies.getSubjectTokenMaxAgeSec(), oidcClient.getId(), tokenIat, now, errorUri);

		var expirationTime = claimsSet.getExpirationTime();
		var subjectTokenNotOnOrAfterToleranceSec = oidcSecurityPolicies.getSubjectTokenNotOnOrAfterToleranceSec();
		var notOnOrAfterToleranceSec = subjectTokenNotOnOrAfterToleranceSec != null ? subjectTokenNotOnOrAfterToleranceSec : trustBrokerPropertiesSecurity.getNotOnOrAfterToleranceSec();
		if (!validNotOnOrAfter(expirationTime, now, notOnOrAfterToleranceSec)) {
			var message = String.format("Expired OIDC %s expiration time %s=%s for client=%s",
					OAuth2ParameterNames.SUBJECT_TOKEN, OidcUtil.OIDC_EXPIRATION_TIME, expirationTime,
					oidcClient.getId());
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_TOKEN, message, errorUri);
		}

		var notBefore = claimsSet.getNotBeforeTime();
		var subjectTokenNotBeforeToleranceSec = oidcSecurityPolicies.getSubjectTokenNotBeforeToleranceSec();
		var notBeforeToleranceSec = subjectTokenNotBeforeToleranceSec != null ? subjectTokenNotBeforeToleranceSec : trustBrokerPropertiesSecurity.getNotBeforeToleranceSec();
		if (!validNotBefore(notBefore, now, notBeforeToleranceSec)) {
			var message = String.format("OIDC %s valid not before %s=%s for client=%s",
					OAuth2ParameterNames.SUBJECT_TOKEN, OidcUtil.OIDC_NOT_BEFORE, notBefore, oidcClient.getId());
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_TOKEN, message, errorUri);
		}
	}

	public static void validIat(Integer maxAgeSex, String clientId, Date tokenIat, long now, String errorUri) {
		// "iat" is OPTIONAL
		if (tokenIat == null) {
			return;
		}

		var iat = tokenIat.getTime();
		if (iat > now) {
			var message = String.format("token is in the future client=%s iat=%s > now", clientId, tokenIat);
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_TOKEN, message, errorUri);
		}
		if (now - iat > (maxAgeSex * 1000L)) {
			var message = String.format("Token is too old for client=%s iat=%s. Allowed tolerance seconds=%s",
					clientId, tokenIat, maxAgeSex);
			CustomOAuth2EndpointUtils.throwErrorWithMessage(OAuth2ErrorCodes.INVALID_TOKEN, message, errorUri);
		}
	}

	public static boolean validNotOnOrAfter(Date check, long now, long notOnOrAfterToleranceSec) {
		// "exp" is OPTIONAL
		if (check == null) {
			return true;
		}

		return now < check.getTime() + (notOnOrAfterToleranceSec * 1000L);
	}

	static boolean validNotBefore(Date check, long now, long notBeforeToleranceSec) {
		// "nbf" is optional
		if (check == null) {
			return true;
		}
		return now >= check.getTime() + (notBeforeToleranceSec * 1000L);
	}

	public static boolean validExpirationLifeTime(Date expirationTime, long now, int expirationLifeTimeSec) {
		// "exp" is OPTIONAL
		if (expirationTime == null) {
			return true;
		}

		long expMs = expirationTime.getTime();
		long maxAllowedExpMs = now + (expirationLifeTimeSec * 1000L);

		// Return false if expiration is too far in the future
		return expMs <= maxAllowedExpMs;
	}

	/**
	 * Validate protocol restrictions on OIDC RP/CP:
	 * - party enabled (with option to override)
	 * - OIDC allowed
	 * @param request optional for canary override - in a request context this will be read from a thread local of missing
	 */
	public static void validateProtocolRestrictions(CounterParty counterParty, String clientId, HttpServletRequest request,
			TrustBrokerProperties trustBrokerProperties) {
		if (RelyingPartySetupUtil.isPartyDisabled(counterParty, request, trustBrokerProperties.getNetwork())) {
			throw OidcExceptionHelper.createOidcException(OAuth2ErrorCodes.INVALID_REQUEST, String.format(
					"Disabled %s issuerId=%s on request='%s %s' in request from %s - clientId=%s",
					counterParty.getClass().getSimpleName(), counterParty.getId(), request.getMethod(), request.getRequestURI(),
					WebSupport.getClientHint(request, trustBrokerProperties.getNetwork()), clientId), "Disabled party");
		}
		validateProtocolRestrictions(counterParty, clientId, trustBrokerProperties);
	}

	/**
	 * Validate restrictions on OIDC RP/CP:
	 * - OIDC allowed
	 */
	public static void validateProtocolRestrictions(CounterParty counterParty, String clientId,
			TrustBrokerProperties trustBrokerProperties) {
		if (!counterParty.isOidcEnabled(trustBrokerProperties.getOidc().isEnabled())) {
			throw OidcExceptionHelper.createOidcException(OAuth2ErrorCodes.INVALID_REQUEST, String.format(
					"%s issuerId=%s does not support OIDC - clientId=%s",
					counterParty.getClass().getSimpleName(), counterParty.getId(), clientId), "OID disabled for party");
		}
	}
}
