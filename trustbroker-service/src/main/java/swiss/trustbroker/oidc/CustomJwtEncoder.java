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

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.oidc.JwtUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;

@Slf4j
@AllArgsConstructor
public class CustomJwtEncoder implements JwtEncoder {

	private final TrustBrokerProperties properties;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final JWKSource<SecurityContext> jwkSource;

	private final OidcEncryptionKeystoreService encryptionKeystoreService;

	@Override
	public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {

		var clientId = (String) parameters.getClaims().getClaim(OidcUtil.OIDC_AUTHORIZED_PARTY);
		var clientConfig = relyingPartyDefinitions.getOidcClientConfigById(clientId, properties);
		var relyingParty = relyingPartyDefinitions.getRelyingPartyByOidcClientId(clientId, null, properties, false);
		if (clientConfig.isEmpty()) {
			throw new TechnicalException(String.format("Could not find config for Client=%s", clientId));
		}

		var isIdToken = OidcUtil.isIdToken(parameters);
		var oidcClient = clientConfig.get();
		var oidcSecurityPolicies = oidcClient.getOidcSecurityPolicies();
		var encryptionEnabled = Boolean.TRUE.equals(oidcSecurityPolicies.getRequireIdTokenEncryption());
		var encryptionParams = encryptionKeystoreService.getEncryptionParams(oidcClient, relyingParty);

		if (encryptionEnabled && encryptionParams == null) {
			log.warn("IdToken encryption enabled but credential is null for Client={}. Skipping encryption", clientId);
			encryptionEnabled = false;
		}

		if (!encryptionEnabled || !isIdToken) {
			log.debug("Encryption disabled for={} or isIdToken={}", clientId, isIdToken);
			var nimbusJwtEncoder = new NimbusJwtEncoder(jwkSource);
			return nimbusJwtEncoder.encode(parameters);
		}

		// JWT in JWE is signed, unsigned token not supported yet
		var jweHeader = OidcUtil.getJWEHeader(encryptionEnabled, encryptionParams.getEncryptionAlgorithm(),
				encryptionParams.getEncryptionMethod(), encryptionParams.getKeyId());
		return JwtUtil.generateEncryptedToken(parameters, encryptionEnabled, this.jwkSource, encryptionParams.getCredential(), jweHeader, clientId);
	}

}
