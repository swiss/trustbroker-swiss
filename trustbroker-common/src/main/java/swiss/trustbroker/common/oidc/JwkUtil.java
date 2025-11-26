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

package swiss.trustbroker.common.oidc;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64URL;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.security.credential.Credential;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import swiss.trustbroker.common.exception.TechnicalException;

/**
 * Util class for Jose JWK.
 */

@Slf4j
@NoArgsConstructor
public class JwkUtil {
    public static String getKeyIdFromJwkSource(JWKSource<SecurityContext> jwkSource) {
        var jwks = getJwkListFromJwkSource(jwkSource);
        if (!jwks.isEmpty()) {
            // Here we rely on the order returned by our own RotateJwkSource, which sends the OLDEST first.
            // I.e. we pick the OLDEST valid key to give calling applications the maximum time to re-fetch our metadata.
            // Some applications do this only at intervals configured on their side.
            var kid = jwks.stream()
                    .map(JWK::getKeyID)
                    .findFirst()
                    .orElseThrow(() -> new TechnicalException("kid not found"));
            log.debug("Picked first JWK with kid={}", kid);
            return kid;
        }
        return null;
    }

    public static List<JWK> getJwkListFromJwkSource(JWKSource<SecurityContext> jwkSource) {
        try {
            var jwkSelector = new JWKSelector(new JWKMatcher.Builder().build());
            return jwkSource.get(jwkSelector, null);
        } catch (KeySourceException e) {
            throw new TechnicalException(String.format("Failed to select the JWK(s) msg=%s", e.getMessage()), e);
        }
    }

	public static JWK createEncrptionJWK(Credential credential, String id, JWEHeader jweHeader) {
		if (credential == null) {
			log.debug("Missing Encryption credential for={}", id);
			return null;
		}

		var keyID = getKeyIdFromHeader(jweHeader);
		var alg = getAlgFromHeader(jweHeader);
		var algFamily = getAlgFamilyFromHeader(jweHeader);

		if (EncAlgFamily.EC.equals(algFamily)) {
			var publicKey = (ECPublicKey) credential.getPublicKey();
			if (publicKey == null) {
				log.warn("Missing EC public for={}", id);
				return null;
			}
			return new ECKey.Builder(Curve.P_256, publicKey)
					.keyID(keyID)
					.algorithm(alg)
					.keyUse(KeyUse.ENCRYPTION)
					.build();
		}

		var publicKey = (RSAPublicKey) credential.getPublicKey();
		if (publicKey == null) {
			log.warn("Missing RSA public for={}", id);
			return null;
		}
		return new RSAKey.Builder(publicKey)
				.keyID(keyID)
				.algorithm(alg)
				.keyUse(KeyUse.ENCRYPTION)
				.build();
	}

	private static JWEAlgorithm getAlgFromHeader(JWEHeader jweHeader) {
		JWEAlgorithm alg = null;
		if (jweHeader != null && jweHeader.getAlgorithm() != null) {
			alg = jweHeader.getAlgorithm();
		}
		else {
			alg = JWEAlgorithm.RSA_OAEP_256;
		}
		return alg;
	}

	private static EncAlgFamily getAlgFamilyFromHeader(JWEHeader jweHeader) {
		var algFamily = EncAlgFamily.RSA;
		if (jweHeader != null && jweHeader.getAlgorithm() != null) {
			var alg = jweHeader.getAlgorithm();
			algFamily = getAlgFamily(alg);
		}
		return algFamily;
	}

	public static EncAlgFamily getAlgFamily(JWEAlgorithm alg) {
		if (alg == null) {
			return EncAlgFamily.RSA;
		}
		return switch (alg.getName()) {
			case "RSA1_5", "RSA-OAEP", "RSA-OAEP-256", "RSA-OAEP-384", "RSA-OAEP-512" -> EncAlgFamily.RSA;
			case "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW" -> EncAlgFamily.EC;
			// NOT supported: "A128KW", "A256KW", "A128GCMKW", "A256GCMKW", "PBES2-HS256+A128KW", "PBES2-HS512+A256KW", "dir"
			default -> throw new TechnicalException("Unsupported JWE algorithm: " + alg.getName());
		};
	}

	private static String getKeyIdFromHeader(JWEHeader jweHeader) {
		String keyID = null;
		if (jweHeader != null && jweHeader.getKeyID() != null) {
			keyID = jweHeader.getKeyID();
		}
		else {
			keyID = UUID.randomUUID().toString();

		}
		return keyID;
	}

	public static JWKMatcher createJwkMatcher(JwsHeader headers, KeyUse keyUse, String id) {
		if (headers == null) {
			throw new TechnicalException(String.format("Missing JWS header for=%s", id));
		}

		var jwkMatcher = JwkUtil.getJwkMatcher(headers.getAlgorithm().getName(), headers.getKeyId(), keyUse, Base64URL.from(headers.getX509SHA256Thumbprint()));
		log.debug("Creating JWK matcher={} for={}", jwkMatcher, id);
		return jwkMatcher;
	}

	public static JWK selectJwk(JWKMatcher jwkMatcher, JWKSource<SecurityContext> jwkSource) {
		List<JWK> jwks;
		try {
			JWKSelector jwkSelector = new JWKSelector(jwkMatcher);
			jwks = jwkSource.get(jwkSelector, null);
		} catch (Exception ex) {
			throw new TechnicalException(String.format("Failed to select a JWK signing key for JwkMatcher=%s with exception=%s", jwkMatcher, ex.getMessage()));
		}
		if (jwks.size() > 1) {
			throw new TechnicalException(String.format("Found multiple JWK signing keys for JwkMatcher=%s", jwkMatcher));
		} else if (jwks.isEmpty()) {
			throw new TechnicalException(String.format("Failed to select a JWK signing key for JwkMatcher=%s", jwkMatcher));
		} else {
			return jwks.get(0);
		}
	}

	public static JWKMatcher getJwkMatcher(String algorithm, String kid, KeyUse keyUse, Base64URL certThumbprint) {
		JWSAlgorithm jwsAlgorithm = JWSAlgorithm.parse(algorithm);

		if (!JWSAlgorithm.Family.RSA.contains(jwsAlgorithm) && !JWSAlgorithm.Family.EC.contains(jwsAlgorithm)) {
			return JWSAlgorithm.Family.HMAC_SHA.contains(jwsAlgorithm) ?
					new JWKMatcher.Builder()
							.keyType(KeyType.forAlgorithm(jwsAlgorithm))
							.keyID(kid).privateOnly(true)
							.algorithm(jwsAlgorithm)
							.build() : null;
		} else {
			return new JWKMatcher.Builder()
					.keyType(KeyType.forAlgorithm(jwsAlgorithm))
					.keyID(kid)
					.keyUses(keyUse, null)
					.algorithms(jwsAlgorithm, null)
					.x509CertSHA256Thumbprint(certThumbprint)
					.build();
		}
	}

	public static JwsHeader buildJwsHeader(JWKSource<SecurityContext> jwkSource) {
		var jwsAlgorithm = SignatureAlgorithm.RS256;
		var jwsHeaderBuilder = JwsHeader.with(jwsAlgorithm);
		var kid = JwkUtil.getKeyIdFromJwkSource(jwkSource);
		if (kid != null) {
			jwsHeaderBuilder.keyId(kid);
		}
		return jwsHeaderBuilder.build();
	}

	public static JWK findEncJwkForAlg(JWKSet jwkSet, String encryptionAlgorithm, String clientId, String protocolEndpoint) {
		if (jwkSet.isEmpty()) {
			log.warn("No JWKs found for protocol client={} endpoint={}", clientId, protocolEndpoint);
			return null;
		}
		var encJwks = jwkSet.getKeys().stream().filter(key -> key != null && key.getKeyUse() == KeyUse.ENCRYPTION).toList();
		if (encJwks.isEmpty()) {
			log.warn("No Encryption JWKs found for protocol client={} endpoint={}", clientId, protocolEndpoint);
			return null;
		}
		if (encJwks.size() == 1) {
			return encJwks.get(0);
		}
		if (encryptionAlgorithm != null) {
			var keyForAlg = encJwks.stream().filter(key -> key != null && key.getAlgorithm() != null &&
					Objects.equals(key.getAlgorithm().getName(), encryptionAlgorithm)).findFirst().orElse(null);
			if (keyForAlg != null) {
				return keyForAlg;
			}
		}
		return encJwks.get(0);
	}
}
