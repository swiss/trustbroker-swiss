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

package swiss.trustbroker.oidcmock;

import java.io.FileNotFoundException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtEncodingException;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.util.ResourceUtils;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.oidc.JwtUtil;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.util.OidcUtil;

@Slf4j
@AllArgsConstructor
public class OidcMockJwtEncoder implements JwtEncoder {

	private final JWKSource<SecurityContext> jwkSource;

	private final OidcMockProperties oidcMockProperties;

	@Override
	public Jwt encode(JwtEncoderParameters parameters) throws JwtEncodingException {

		boolean encryptIdToken = oidcMockProperties.isEncryptIdToken();
		boolean signToken = oidcMockProperties.isSignEncIdToken();

		var isIdToken = OidcUtil.isIdToken(parameters);

		if (!encryptIdToken || !isIdToken) {
			var nimbusJwtEncoder = new NimbusJwtEncoder(jwkSource);
			return nimbusJwtEncoder.encode(parameters);
		}
		var encryptionCredential = getEncryptionCredential();
		boolean requireTokenSignedEncryption = encryptIdToken && signToken;

		var jweHeader = OidcUtil.getJWEHeader(requireTokenSignedEncryption, oidcMockProperties.getEncryptionAlgorithm(), oidcMockProperties.getEncryptionMethod(), null);

		return JwtUtil.generateEncryptedToken(parameters, signToken, this.jwkSource, encryptionCredential, jweHeader, "OidcMockClient");
	}

	private Credential getEncryptionCredential() {
		var certificate = getCertificate();
		var privateKey = generatePrivetKey();

		var basicCredential = new BasicCredential();
		basicCredential.setPrivateKey(privateKey);
		basicCredential.setPublicKey(certificate.getPublicKey());

		return basicCredential;
	}

	public PrivateKey generatePrivetKey() {
		try {
			var file = ResourceUtils.getFile("classpath:enc-private-key.pem");
			return CredentialReader.readPemPrivateKey(file.getAbsolutePath(), "changeit");
		} catch (FileNotFoundException e) {
			throw new RequestDeniedException(e.getMessage());
		}
	}

	public Certificate getCertificate() {
		try {
			var file = ResourceUtils.getFile("classpath:enc-private-key.pem");
			return CredentialReader.readPemCertificate(file.getAbsolutePath());
		} catch (FileNotFoundException e) {
			throw new RequestDeniedException(e.getMessage());
		}
	}
}
