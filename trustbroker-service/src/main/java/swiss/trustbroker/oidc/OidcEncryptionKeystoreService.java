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

import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.oidc.JwkUtil;
import swiss.trustbroker.common.oidc.JwtUtil;
import swiss.trustbroker.config.CredentialService;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.oidc.cache.service.OidcMetadataCacheService;


/**
 * Service for OIDC Encryption Keystore loading
 *
 */
@Service
@AllArgsConstructor
@Slf4j
public class OidcEncryptionKeystoreService {

	private final CredentialService credentialService;

	private final OidcMetadataCacheService metadataCacheService;

	@Getter
	@Builder
	public static class EncryptionParams {
		private Credential credential;
		private String keyId;
		private String encryptionAlgorithm;
		private String encryptionMethod;
	}

	public void loadClientsEncKeystore(String id, String subPath, List<OidcClient> oidcClients) {
		for (OidcClient oidcClient : oidcClients) {
			if (oidcClient.getCertificates() != null && oidcClient.getCertificates().getEncryptionTruststore() != null) {
				var encryptionKeystore = oidcClient.getCertificates().getEncryptionTruststore();
				var encKeystore = credentialService.checkAndLoadTrustCredential(encryptionKeystore, id, subPath);
				if (encKeystore != null) {
					oidcClient.setClientEncryptionCredential(encKeystore.get(0));
				}
			}
		}
	}

	public void loadClientsDecryptionKeystore(String id, String subPath, List<OidcClient> oidcClients) {
		for (OidcClient oidcClient : oidcClients) {
			if (oidcClient.getCertificates() != null && oidcClient.getCertificates().getEncryptionKeystore() != null) {
				var encryptionKeystore = oidcClient.getCertificates().getEncryptionKeystore();
				var encKeystore = credentialService.checkAndLoadCert(encryptionKeystore, id, subPath);
				oidcClient.setClientEncryptionCredential(encKeystore);
			}
		}
	}

	private JWK getJwkFromCache(OidcClient oidcClient, RelyingParty relyingParty) {
		if (oidcClient.getProtocolEndpoints() == null) {
			return null;
		}
		log.debug("Pulling JWKs from endpoint={}", oidcClient.getProtocolEndpoints());
		var encryptionAlgorithm = oidcClient.getOidcSecurityPolicies().getEncryptionAlgorithm();
		var openIdProviderConfiguration = metadataCacheService.getOidcConfiguration(relyingParty, oidcClient);
		if (openIdProviderConfiguration != null && openIdProviderConfiguration.getJwkSet() != null) {
			var jwkSet = openIdProviderConfiguration.getJwkSet();
			log.debug("JWKs={} pulled from protocol endpoint={}", jwkSet.size(), oidcClient.getProtocolEndpoints());
			return JwkUtil.findEncJwkForAlg(jwkSet, encryptionAlgorithm, oidcClient.getId(), oidcClient.getProtocolEndpoints().getMetadataUrl());
		}
		return null;
	}

	public EncryptionParams getEncryptionParams(OidcClient oidcClient, RelyingParty relyingParty) {
		var encryptionCredential = oidcClient.getClientEncryptionCredential();

		var securityPolicies = oidcClient.getOidcSecurityPolicies();
		String alg = null;
		String method = null;
		String keyId = null;
		if (securityPolicies != null) {
			alg = securityPolicies.getEncryptionAlgorithm();
			method = securityPolicies.getEncryptionMethod();
			keyId = securityPolicies.getEncryptionKid();
		}

		if (encryptionCredential == null && oidcClient.getProtocolEndpoints() != null) {
			var jwk = getJwkFromCache(oidcClient, relyingParty);
			if (jwk != null) {
				keyId = jwk.getKeyID();
				log.debug("Found encryption kid={} for protocol endpoint={}",keyId, oidcClient.getProtocolEndpoints());
				alg = jwk.getAlgorithm() != null ? jwk.getAlgorithm().getName() : alg;
				encryptionCredential = new BasicX509Credential(jwk.getParsedX509CertChain().get(0));
			}
			else {
				log.warn("JWK not found for protocol endpoint={}",oidcClient.getProtocolEndpoints());
				return null;
			}
		}

		method = method != null ? method : JwtUtil.getRecommendedEncryptionMethod(alg);
		if (encryptionCredential != null) {
			return EncryptionParams.builder().credential(encryptionCredential).keyId(keyId).encryptionAlgorithm(alg).encryptionMethod(method).build();
		}

		return null;
	}
}
