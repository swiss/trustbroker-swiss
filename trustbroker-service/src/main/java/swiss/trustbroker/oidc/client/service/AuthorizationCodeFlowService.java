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

package swiss.trustbroker.oidc.client.service;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.OidcClaimsSource;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.Scope;
import swiss.trustbroker.mapping.dto.QoaSpec;
import swiss.trustbroker.oidc.cache.service.OidcMetadataCacheService;
import swiss.trustbroker.oidc.client.dto.AuthorizationCodeFlowRequest;
import swiss.trustbroker.oidc.client.dto.OpenIdProviderConfiguration;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.util.ApiSupport;

/**
 * OIDC client for Authorization Code Flow.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth">OIDC Authorization Code Flow</a>
 */
@Component
@AllArgsConstructor
@Slf4j
public class AuthorizationCodeFlowService {

	private final ApiSupport apiSupport;

	private final OidcMetadataCacheService oidcMetadataCacheService;

	private final OidcTokenService oidcTokenService;

	private final OidcUserinfoService userinfoService;

	private final JwtClaimsService jwtClaimsService;

	private final OidcClaimValidatorService oidcClaimValidatorService;

	private final TrustBrokerProperties trustBrokerProperties;

	/**
	 * Create Authorization Code Flow request URL with its parameters for auditing.
	 */
	public AuthorizationCodeFlowRequest createAuthnRequest(ClaimsParty claimsParty, StateData stateData, QoaSpec qoaSpec, String queryParam) {
		var client = claimsParty.getSingleOidcClient();
		var scopes = client.hasScopes() ?
				client.getScopes().getScopeList() :
				Scope.defaultNames();
		var redirectUri = apiSupport.getOidcResponseApi(client.getRealm());
		var configuration = oidcMetadataCacheService.getOidcConfiguration(claimsParty);
		var result = buildCodeFlowAuthorizationRequest(client, claimsParty, configuration, stateData, qoaSpec, scopes,
				redirectUri, queryParam);
		log.info("OIDC authorization code flow for cpIssuerId={} clientId={} sessionId={} "
						+ "redirecting to requestUri=\"{}\"",
				claimsParty.getId(), result.clientId(), stateData.getId(), result.requestUri());
		return result;
	}

	/**
	 * Process response to Authorization Code Flow request, fetch tokens, and convert to <codeCpResponse></code>.
	 */
	public CpResponse handleCpResponse(String realm, String code, ClaimsParty claimsParty, StateData stateData) {
		log.info("Processing code response for sessionId={} realm={}", stateData.getId(), realm);
		var client = claimsParty.getSingleOidcClient();
		// realm should match, but technically and security-wise not relevant
		if (realm != null && !realm.equals(client.getRealm())) {
			log.warn("Inbound realm={} does not match clientId={} clientRealm={} for sessionId={}",
					realm, client.getId(), client.getRealm(), stateData.getId());
		}
		// fetch tokens (back-channel):
		var configuration = oidcMetadataCacheService.getOidcConfiguration(claimsParty);
		var keySupplier = jwtKeySupplier(claimsParty);
		var redirectUri = apiSupport.getOidcResponseApi(client.getRealm());
		var tokenResponse = oidcTokenService.fetchTokens(client, claimsParty.getCertificates(), configuration, redirectUri, code);
		var idTokenClaims = getClaimsFromIdToken(claimsParty, stateData, client, configuration, tokenResponse, keySupplier);
		var userinfoClaims = getClaimsFromUserinfo(claimsParty, client, tokenResponse, configuration, keySupplier);
		var claims = mergeClaims(client, idTokenClaims, userinfoClaims);
		return buildCpResponseFromClaims(claimsParty, client, claims);
	}

	private JWTClaimsSet getClaimsFromIdToken(ClaimsParty claimsParty, StateData stateData, OidcClient client,
			OpenIdProviderConfiguration configuration, Map<String, Object> tokenResponse,
			Function<String, Optional<JWK>> keySupplier) {
		if (!client.useClaimsFromSource(OidcClaimsSource.ID_TOKEN)) {
			log.debug("No claims from {} required", OidcUtil.TOKEN_RESPONSE_ID_TOKEN);
			return null;
		}
		var idToken = tokenResponse.get(OidcUtil.TOKEN_RESPONSE_ID_TOKEN);
		if (!(idToken instanceof String idTokenString)) {
			throw new RequestDeniedException(
					String.format("Did not receive OIDC %s from client=%s tokenEndpoint=%s",
							OidcUtil.TOKEN_RESPONSE_ID_TOKEN, client.getId(), configuration.getTokenEndpoint()));
		}
		var cpDecryptionCredential = client.getClientEncryptionCredential();
		var claims = OidcUtil.decryptAndVerifyToken(idTokenString, keySupplier, cpDecryptionCredential, client.getId());
		log.debug("OIDC {} client={} tokenEndpoint={} claims={}", OidcUtil.TOKEN_RESPONSE_ID_TOKEN, client.getId(),
				configuration.getTokenEndpoint(), claims);
		oidcClaimValidatorService.validateClaims(claims, claimsParty, client, configuration.getIssuerId(),
				stateData.getSpStateData().getOidcNonce());
		return claims;
	}

	private JWTClaimsSet getClaimsFromUserinfo(ClaimsParty claimsParty, OidcClient client,
			Map<String, Object> tokenResponse, OpenIdProviderConfiguration configuration,
			Function<String, Optional<JWK>> keySupplier) {
		if (!client.useClaimsFromSource(OidcClaimsSource.USERINFO)) {
			log.debug("No claims from userinfo required");
			return null;
		}
		log.debug("OIDC client={} requires call to userinfo", client.getId());
		var accessToken = tokenResponse.get(OidcUtil.TOKEN_RESPONSE_ACCESS_TOKEN);
		if (!(accessToken instanceof String accessTokenString)) {
			throw new RequestDeniedException(
					String.format("Did not receive OIDC %s from client=%s tokenEndpoint=%s",
							OidcUtil.TOKEN_RESPONSE_ACCESS_TOKEN, client.getId(), configuration.getTokenEndpoint()));
		}
		var claims = userinfoService.fetchUserInfo(client, claimsParty.getCertificates(), configuration,
				accessTokenString, keySupplier);
		log.debug("OIDC client={} userinfoEndpoint={} returned claims={}",
				client.getId(), configuration.getUserinfoEndpoint(), claims);
		return claims;
	}

	static JWTClaimsSet mergeClaims(OidcClient client, JWTClaimsSet idTokenClaims, JWTClaimsSet userinfoClaims) {
		JWTClaimsSet claims = null;
		OidcClaimsSource claimsSource = null;
		for (var source : client.getClaimsSources().getClaimsSourceList()) {
			var sourceClaims = switch (source) {
				case ID_TOKEN -> idTokenClaims;
				case USERINFO -> userinfoClaims;
			};
			claims = OidcUtil.mergeJwtClaims(claims, claimsSource != null ? claimsSource.name() : null,
					sourceClaims, source.name());
			claimsSource = source;
		}
		log.debug("OIDC client={} merged from sources={} claims={}",
				client.getId(), client.getClaimsSources().getClaimsSourceList(), claims);
		if (claims == null) {
			// should not happen due to default
			throw new TechnicalException(String.format("OIDC client=%s has no ClaimsSources", client.getId()));
		}
		return claims;
	}

	private Function<String, Optional<JWK>> jwtKeySupplier(ClaimsParty claimsParty) {
		return id -> oidcMetadataCacheService.getKey(claimsParty, id);
	}

	private CpResponse buildCpResponseFromClaims(ClaimsParty claimsParty, OidcClient oidcClient, JWTClaimsSet claims) {
		var attributes = jwtClaimsService.mapClaimsToAttributes(claims, claimsParty);
		if (claimsParty.getHomeName() == null) {
			throw new TechnicalException(String.format("Missing HomeName for cpIssuerId=%s", claimsParty.getId()));
		}
		var contextClasses = jwtClaimsService.getCtxClasses(claims, claimsParty);
		return CpResponse.builder()
								   .issuer(claimsParty.getId()) // use CP ID, claims.issuer can be OidcClient.issuerId
								   .nameId(claims.getSubject())
								   .claims(claims.getClaims())
						 		   .homeName(claimsParty.getHomeName().getName())
								   .attributes(attributes)
						 	       .oidcClientId(oidcClient.getId())
								   .contextClasses(contextClasses)
								   .build();
	}

	private AuthorizationCodeFlowRequest buildCodeFlowAuthorizationRequest(OidcClient client, ClaimsParty claimsParty,
																		   OpenIdProviderConfiguration providerConfiguration, StateData stateData, QoaSpec qoaSpec, List<String> scopes,
																		   String redirectUri, String queryParam) {
		var endpointUri = providerConfiguration.getAuthorizationEndpoint();
		var scopeString = String.join(" ", scopes);
		var qoaString = String.join(" ", qoaSpec.contextClasses());
		// audience not sent
		var endpoint = endpointUri.toString();
		var queryString = new StringBuilder(endpoint)
				// we only support code flow so far
				.append("?response_type=code&response_mode=")
				.append(client.getResponseMode().getName())
				.append("&client_id=")
				.append(WebUtil.urlEncodeValue(client.getId()))
				.append("&state=")
				.append(WebUtil.urlEncodeValue(stateData.getSpStateData().getId()))
				.append("&scope=")
				.append(WebUtil.urlEncodeValue(scopeString))
				.append("&nonce=")
					.append(WebUtil.urlEncodeValue(stateData.getSpStateData().getOidcNonce()))
				.append("&redirect_uri=")
				.append(WebUtil.urlEncodeValue(redirectUri));
		var forceAuthn = stateData.forceAuthn()
				|| claimsParty.forceAuthn(trustBrokerProperties.getSecurity().isForceCpAuthentication());
		// Do not add prompt=login if the query param is manipulated in a Groovy script
		if (forceAuthn && queryParam == null) {
			queryString.append("&prompt=login");
		}
		// Do not add acr_values if the query param is manipulated in a Groovy script
		if (queryParam == null) {
			queryString.append("&acr_values=")
					   .append(WebUtil.urlEncodeValue(qoaString));
		}
		else {
			queryString.append("&").append(queryParam);
		}
		// concat as URI::resolve cuts the last part of path without trailing slash, e.g. trailing /authorize is lost
		var uri = WebUtil.getValidatedUri(queryString.toString());
		var request = uri.toString();
		log.debug("OIDC authorization request to authorizationEndpoint={} for clientId={} state={} scope={} redirectUri={} "
						+ "is authorizationRequest=\"{}\"",
				endpoint, client.getId(), stateData.getId(), scopes, redirectUri, request);
		return AuthorizationCodeFlowRequest.builder()
										   .clientId(client.getId())
										   .scopes(scopes)
										   .acrValues(qoaSpec.contextClasses())
										   .forceAuthn(forceAuthn)
										   .destination(endpoint)
										   .assertionConsumerUrl(redirectUri)
										   .requestUri(request)
										   .build();
	}
}
