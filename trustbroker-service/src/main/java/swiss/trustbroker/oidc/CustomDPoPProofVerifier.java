/*
 * Derivative work of original class from org.springframework.security:spring-security-oauth2-authorization-server:1.2.4:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider
 *
 * https://spring.io/projects/spring-authorization-server
 *
 * License of original class:
 *
 * @license
 *
 * Copyright 2020-2024 the original author or authors.
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

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.DPoPProofContext;
import org.springframework.security.oauth2.jwt.DPoPProofJwtDecoderFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.StringUtils;

/**
 * Copied from spring-security-oauth2-authorization-server:
 * org.springframework.security.oauth2.server.authorization.authentication.DPoPProofVerifier
 * That class is final and the method package private.
 * So we cannot re-use that code.
 * invalidate is unchanged.
 * The copying means we are tied to an internal class from Spring Authentication Server.
 * <p>
 * Original Javadoc:
 * A verifier for DPoP Proof Jwt's.
 * DPoPProofJwtDecoderFactory, RFC 9449 OAuth 2.0 Demonstrating Proof of Possession (DPoP)
 *
 * @author Joe Grandja
 * @since 1.5
 */

@Slf4j
public class CustomDPoPProofVerifier {

	private static final JwtDecoderFactory<DPoPProofContext> dPoPProofVerifierFactory = new DPoPProofJwtDecoderFactory();

	private CustomDPoPProofVerifier() {
	}

	static Jwt verifyIfAvailable(OAuth2AuthorizationGrantAuthenticationToken authorizationGrantAuthentication) {
		String dPoPProof = (String) authorizationGrantAuthentication.getAdditionalParameters().get("dpop_proof");
		if (!StringUtils.hasText(dPoPProof)) {
			return null;
		}

		String method = (String) authorizationGrantAuthentication.getAdditionalParameters().get("dpop_method");
		String targetUri = (String) authorizationGrantAuthentication.getAdditionalParameters().get("dpop_target_uri");

		org.springframework.security.oauth2.jwt.Jwt dPoPProofJwt;
		try {
			// @formatter:off
			DPoPProofContext dPoPProofContext = DPoPProofContext.withDPoPProof(dPoPProof)
																.method(method)
																.targetUri(targetUri)
																.build();
			// @formatter:on
			JwtDecoder dPoPProofVerifier = dPoPProofVerifierFactory.createDecoder(dPoPProofContext);
			dPoPProofJwt = dPoPProofVerifier.decode(dPoPProof);
		}
		catch (Exception ex) {
			log.error("DPoP Proof verification failed", ex);
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF), ex);
		}

		return dPoPProofJwt;
	}
}
