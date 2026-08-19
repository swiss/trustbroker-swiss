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

package swiss.trustbroker.oidc.client.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.micrometer.core.annotation.Timed;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.tracing.Traced;
import swiss.trustbroker.common.util.HttpUtil;
import swiss.trustbroker.common.util.JsonUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.federation.xmlconfig.AuthorizationGrantType;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.ClientAuthenticationMethod;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.OidcHttpClientProvider;
import swiss.trustbroker.oidc.client.dto.OpenIdProviderConfiguration;

/**
 * Service for fetching tokens from an OIDC CP.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint">OIDC 1.0 Token Endpoint</a>
 */
@Service
@AllArgsConstructor
@Slf4j
class OidcTokenService {

	private final OidcHttpClientProvider httpClientProvider;

	@Traced
	@Timed("oidc_token_fetch")
	public Map<String, Object> fetchTokens(OidcClient client, Certificates certificates,
			OpenIdProviderConfiguration configuration, String redirectUri, String code) {
		String clientSecretPost = null;
		Map<String, String> headers = new HashMap<>();
		var authenticationMethod = selectAuthenticationMethod(client, configuration);
		if (authenticationMethod == ClientAuthenticationMethod.CLIENT_SECRET_POST) {
			clientSecretPost = configuration.getClientSecret();
		}
		else {
			var authorization = OidcUtil.getBasicAuthorizationHeader(client.getId(), configuration.getClientSecret());
			headers.put(HttpHeaders.AUTHORIZATION, authorization);
		}
		var params = buildTokenRequestParameters(client, code, redirectUri, clientSecretPost);
		var tokenEndpoint = configuration.getTokenEndpoint();
		if (log.isDebugEnabled()) {
			log.debug("HTTP POST to tokenEndpoint={} redirectUri={} params={}",
					tokenEndpoint, redirectUri, StringUtil.maskSecrets(params.toString(), clientSecretPost, code));
		}
		try (var httpClient = httpClientProvider.createHttpClient(client, certificates, tokenEndpoint)) {
			var responseOpt = HttpUtil.getHttpFormPostStringResonse(httpClient, tokenEndpoint, params, headers);
			if (responseOpt.isEmpty()) {
				throw new TechnicalException(String.format("oidcClientId=%s failed POST to tokenEndpoint=%s",
						client.getId(), tokenEndpoint));
			}
			var response = responseOpt.get();
			if (response.statusCode() != HttpStatus.OK.value()) {
				throw new TechnicalException(String.format(
						"oidcClientId=%s POST to tokenEndpoint=%s returned HTTP statusCode=%d body='%s'",
						client.getId(), tokenEndpoint, response.statusCode(), response.body()));
			}
			return JsonUtil.parseJsonObject(response.body(), false);
		}
	}

	private static Map<String, String> buildTokenRequestParameters(OidcClient client, String code,
			String redirectUri, String clientSecret) {
		Map<String, String> params = new HashMap<>();
		params.put(OidcUtil.CODE, code);
		params.put(OidcUtil.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.name().toLowerCase());
		params.put(OidcUtil.REDIRECT_URI, redirectUri);
		if (clientSecret != null) {
			// client secret post
			params.put(OidcUtil.OIDC_CLIENT_ID, client.getId());
			params.put(OidcUtil.CLIENT_SECRET, clientSecret);
		}
		return params;
	}

	static ClientAuthenticationMethod selectAuthenticationMethod(OidcClient client,
			OpenIdProviderConfiguration configuration) {
		List<ClientAuthenticationMethod> authenticationMethods =
				new ArrayList<>(configuration.getAuthenticationMethods().getMethods());
		if (client.getClientAuthenticationMethods() != null) {
			authenticationMethods.retainAll(client.getClientAuthenticationMethods().getMethods());
			log.debug("Possible for issuerId={} : authenticationMethods={}", configuration.getIssuerId(), authenticationMethods);
		}
		boolean clientSecretBasicSupported = authenticationMethods.contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		boolean clientSecretPostSupported = authenticationMethods.contains(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		if (clientSecretPostSupported && !clientSecretBasicSupported) {
			log.debug("Using client_secret_post");
			return ClientAuthenticationMethod.CLIENT_SECRET_POST;
		}
		if (clientSecretBasicSupported) {
			log.debug("Using client_secret_basic");
		}
		else {
			log.warn("None of the authenticationMethods={} of client={} supported, using client_secret_basic",
					authenticationMethods, client.getId());
		}
		return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
	}

}
