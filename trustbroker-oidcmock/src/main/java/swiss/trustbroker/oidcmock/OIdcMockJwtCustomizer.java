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

package swiss.trustbroker.oidcmock;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import swiss.trustbroker.common.util.OidcUtil;

@AllArgsConstructor
@Slf4j
public class OIdcMockJwtCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private final JWKSource<SecurityContext> jwkSource;

	private final OidcMockUserInfoService userInfoService;

	private final OidcMockProperties oidcMockProperties;

	private final List<String> oidcParams = List.of("code", "state", "client_secret", "client_id", "grant_type", "redirect_uri");

	private final List<String> authorizeParams = List.of("nonce", "continue", "response_mode");

	@Override
	public void customize(JwtEncodingContext context) {
		if (context == null) {
			return;
		}

		Map<String, Object> customClaims = extractCustomClaimsFromReqParams();

		var authorization = context.getAuthorization();
		if (authorization == null) {
			throw new RequestRejectedException("Missing authorization, cannot set Token claims");
		}

		extractCustomClaimsFromAuthorizeReq(authorization, customClaims);

		var clientId = authorization.getRegisteredClientId();
		addConfigClaims(clientId, customClaims);

		if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			OidcUserInfo userInfo = userInfoService.loadUser(
					context.getPrincipal().getName());
			context.getClaims().claims(claims -> claims.putAll(userInfo.getClaims()));
		}

		for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
			context.getClaims().claim(entry.getKey(), entry.getValue());
		}

		generateDPoP(jwkSource);
	}

	private static void generateDPoP(JWKSource<SecurityContext> jwkSource) {
		try {
			var claims = new JWTClaimsSet.Builder()
					.claim("htm", "POST")
					.claim("htu", "http://localhost:8080/realms/XTB-dev/protocol/openid-connect/token")
					.issueTime(new Date())
					.jwtID(UUID.randomUUID().toString())
					// Optional: .claim("ath", base64urlSHA256(accessToken))
					.build();
			var jwkSelector = new JWKSelector(new JWKMatcher.Builder().build());
			List<JWK> jwks = jwkSource.get(jwkSelector, null);
			var signer = new RSASSASigner(jwks.get(0).toRSAKey());
			var publicJWK = jwks.get(0).toPublicJWK();
			var signedJWT = new SignedJWT(
					new JWSHeader.Builder(JWSAlgorithm.RS256)
							.type(new JOSEObjectType("dpop+jwt"))
							.jwk(publicJWK)
							.build(),
					claims
			);
			signedJWT.sign(signer);
			var dpopJwt = signedJWT.serialize();
			log.info("Generated DPOP JWT: {}", dpopJwt);
		}
		catch (Exception ex) {
			log.error(ex.getMessage(), ex);
		}
	}

	private void addConfigClaims(String clientId, Map<String, Object> customClaims) {
		Map<String, String> config = oidcMockProperties.getClients().get(clientId);
		if (config != null) {
			customClaims.putAll(config);
		}
	}

	private void extractCustomClaimsFromAuthorizeReq(OAuth2Authorization authorization, Map<String, Object> customClaims) {
		var authorizeRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
		if (authorizeRequest instanceof OAuth2AuthorizationRequest oAuth2AuthorizationRequest) {
			Map<String, Object> additionalParameters = oAuth2AuthorizationRequest.getAdditionalParameters();
			if (additionalParameters != null) {
				addAdditionalParameters(customClaims, additionalParameters);
			}
		}
	}

	private void addAdditionalParameters(Map<String, Object> customClaims, Map<String, Object> additionalParameters) {
		for (Map.Entry<String, Object> entry : additionalParameters.entrySet()) {
			var key = entry.getKey();
			var value = entry.getValue().toString();
			if (key != null && !authorizeParams.contains(key)) {
				if ("acr_values".equals(key)) {
					customClaims.put("acr", OidcUtil.convertAcrToContextClasses(value).toArray());
				}
				else {
					customClaims.put(key, value);
				}
			}
		}
	}

	private Map<String, Object> extractCustomClaimsFromReqParams() {
		Map<String, Object> customClaims = new HashMap<>();

		RequestAttributes request = RequestContextHolder.getRequestAttributes();
		HttpServletRequest httpServletRequest = null;
		if (request instanceof ServletRequestAttributes sra) {
			httpServletRequest = sra.getRequest();
		}

		if (httpServletRequest == null) {
			return customClaims;
		}

		Map<String, String[]> parameterMap = httpServletRequest.getParameterMap();

		for (Map.Entry<String, String[]> entry : parameterMap.entrySet()) {
			if (!oidcParams.contains(entry.getKey())) {
				customClaims.put(entry.getKey(), entry.getValue()[0]);
			}
		}
		return customClaims;
	}
}
