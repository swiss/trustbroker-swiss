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

package swiss.trustbroker.oidc;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.oidc.JwkUtil;
import swiss.trustbroker.common.oidc.JwtUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;

@AllArgsConstructor
@Slf4j
public class CustomUserInfoResponseHandler implements AuthenticationSuccessHandler {

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	private final ObjectMapper objectMapper;

	private final JWKSource<SecurityContext> jwkSource;

	private final OidcEncryptionKeystoreService encryptionKeystoreService;

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		if (!authentication.isAuthenticated()) {
			throw new RequestDeniedException("Userinfo Authentication failed");
		}

		if (authentication instanceof OidcUserInfoAuthenticationToken userInfoAuthenticationToken) {

			var clientId = extractClientIdFromClaims(userInfoAuthenticationToken);

			var clientConfig = relyingPartyDefinitions.getOidcClientConfigById(clientId, trustBrokerProperties);
			var relyingParty = relyingPartyDefinitions.getRelyingPartyByOidcClientId(clientId, null, trustBrokerProperties, false);
			if (clientConfig.isEmpty()) {
				throw new TechnicalException("Could not find client config for " + clientId);
			}

			var claims = userInfoAuthenticationToken.getUserInfo().getClaims();

			var oidcClient = clientConfig.get();
			var userInfoResponseEncryption = Boolean.TRUE.equals(
					oidcClient.getOidcSecurityPolicies().getRequireUserInfoResponseEncryption());

			var encryptionParams = encryptionKeystoreService.getEncryptionParams(oidcClient, relyingParty);

			if (userInfoResponseEncryption && encryptionParams != null) {
				encryptUserInfoResponse(response, claims, encryptionParams, clientId);
			}
			else {
				setJwtResponseAttributes(response, claims);
			}
		}
		else {
			log.error("Unsupported authentication type: {}", authentication.getClass());
		}
	}

	private void encryptUserInfoResponse(HttpServletResponse response, Map<String, Object> claims, OidcEncryptionKeystoreService.EncryptionParams encryptionParams, String clientId) {
		var claimsSetBuilder = new JWTClaimsSet.Builder();
		claims.forEach(claimsSetBuilder::claim);
		var claimsSet = claimsSetBuilder.build();

		var jweHeader = OidcUtil.getJWEHeader(true, encryptionParams.getEncryptionAlgorithm(), encryptionParams.getEncryptionMethod(), encryptionParams.getKeyId());
		var jwk = JwkUtil.createEncrptionJWK(encryptionParams.getCredential(), clientId, jweHeader);
		if (jwk == null) {
			log.warn("Couldn't create Encryption JWK for={}. Skipping UserInfo response encryption", clientId);
			setJwtResponseAttributes(response, claims);
			return;
		}

		// LATER The response MAY be encrypted without also being signed https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
		var payload = OidcUtil.getAndSignPayload(claimsSet, true, JwkUtil.buildJwsHeader(jwkSource), jwkSource, clientId);
		String encryptJwt = null;
		try {
			log.debug("Sending encrypted UserInfo response to={}", clientId);
			encryptJwt = JwtUtil.encryptJwt(jweHeader, payload, jwk);
			response.setContentType(JwtUtil.APPLICATION_JWT_TYPE);
			response.getOutputStream().write(encryptJwt.getBytes(StandardCharsets.UTF_8));
		}
		catch (JOSEException e) {
			throw new TechnicalException(String.format("JWT encryption failed: message=\"%s\"", e.getMessage()), e);
		}
		catch (IOException e) {
			throw new TechnicalException("Could not send userinfo response", e);
		}
	}

	private String extractClientIdFromClaims(OidcUserInfoAuthenticationToken userInfoAuthenticationToken) {
		Object aud = null;
		if (userInfoAuthenticationToken.getPrincipal() instanceof JwtAuthenticationToken jwt) {
			aud = jwt.getTokenAttributes().get(OidcUtil.OIDC_AUDIENCE);
		}

		if (userInfoAuthenticationToken.getPrincipal() instanceof BearerTokenAuthentication bearerTokenAuthentication) {
			aud = bearerTokenAuthentication.getTokenAttributes().get(OidcUtil.OIDC_AUDIENCE);
		}

		if (aud instanceof String audString) {
			return audString;
		}
		if (aud instanceof Collection<?> audiences) {
			var audClaims = Arrays.stream(audiences.toArray()).toList();
			if (audClaims.size() == 1) {
				return audClaims.get(0).toString();
			}
		}
		return null;
	}

	private void setJwtResponseAttributes(HttpServletResponse response, Map<String, Object> claims) {
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		try {
			objectMapper.writeValue(response.getOutputStream(), claims);
		}
		catch (IOException ex) {
			throw new TechnicalException("Could not send userinfo response", ex);
		}
	}
}
