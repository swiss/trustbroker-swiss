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

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import io.micrometer.core.annotation.Timed;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.MimeType;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.tracing.Traced;
import swiss.trustbroker.common.util.HttpUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.oidc.OidcHttpClientProvider;
import swiss.trustbroker.oidc.client.dto.OpenIdProviderConfiguration;

/**
 * Service for fetching user info from an OIDC CP.
 *
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo">OIDC 1.0 UserInfo Endpoint</a>
 */
@Service
@AllArgsConstructor
@Slf4j
class OidcUserinfoService {

	private final OidcHttpClientProvider httpClientProvider;

	@Traced
	@Timed("oidc_userinfo_fetch")
	public JWTClaimsSet fetchUserInfo(OidcClient client, Certificates certificates,
			OpenIdProviderConfiguration configuration, String accessToken, Function<String, Optional<JWK>> keySupplier) {
		var authorization = OidcUtil.getBearerAuthorizationHeader(accessToken);
		Map<String, String> headers = new HashMap<>();
		headers.put(HttpHeaders.AUTHORIZATION, authorization);
		var userinfoEndpoint = configuration.getUserinfoEndpoint();
		log.debug("HTTP GET to userinfoEndpoint={}", userinfoEndpoint);
		var httpClient = httpClientProvider.createHttpClient(client, certificates, userinfoEndpoint);
		var response = HttpUtil.getHttpStringResponse(httpClient, userinfoEndpoint, headers);
		if (response.isEmpty()) {
			throw new TechnicalException(String.format("oidcClientId=%s failed GET to userinfoEndpoint=%s",
					client.getId(), userinfoEndpoint));
		}
		var httpResponse = response.get();
		var contentType = httpResponse.headers().firstValue(HttpHeaders.CONTENT_TYPE);
		log.info("HTTP GET to userinfoEndpoint={} returned {}={}",
				userinfoEndpoint, HttpHeaders.CONTENT_TYPE, contentType.orElse(null));
		if (!contentType.isPresent()) {
			throw new TechnicalException(String.format("oidcClientId=%s GET to userinfoEndpoint=%s returned no %s header",
					client.getId(), userinfoEndpoint, HttpHeaders.CONTENT_TYPE));
		}
		var mimeType = MimeType.valueOf(contentType.get());
		if (mimeType.equalsTypeAndSubtype(MediaType.APPLICATION_JSON)) {
			return OidcUtil.parseJwtClaims(httpResponse.body());
		}
		if (mimeType.equalsTypeAndSubtype(OidcUtil.MIME_TYPE_JWT)) {
			return OidcUtil.verifyJwtToken(httpResponse.body(), keySupplier::apply, client.getId());
		}
		throw new TechnicalException(String.format("oidcClientId=%s GET to userinfoEndpoint=%s returned unsupported %s=%s ",
				client.getId(), userinfoEndpoint, HttpHeaders.CONTENT_TYPE, contentType.get()));
	}

}
