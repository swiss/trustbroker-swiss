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

import java.security.cert.X509Certificate;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.X509Credential;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.stereotype.Component;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.OidcIdentityProvider;
import swiss.trustbroker.config.dto.OidcProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;

@Component
public class CustomRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final OidcProperties oidcProperties;

	private final TrustBrokerProperties trustBrokerProperties;

	private Credential signer;

	public CustomRelyingPartyRegistrationRepository(RelyingPartyDefinitions relyingPartyDefinitions,
			OidcProperties oidcProperties, TrustBrokerProperties trustBrokerProperties) {
		this.relyingPartyDefinitions = relyingPartyDefinitions;
		this.oidcProperties = oidcProperties;
		this.trustBrokerProperties = trustBrokerProperties;
		signer = CredentialReader.createCredential(trustBrokerProperties.getSigner());
	}

	@Override
	public RelyingPartyRegistration findByRegistrationId(String registrationId) {
		var oidcClient = relyingPartyDefinitions.getOidcClientConfigById(registrationId, trustBrokerProperties);
		if (oidcClient.isPresent()) {
			var samlRp = relyingPartyDefinitions.getRelyingPartyByOidcClientId(registrationId, null,
					trustBrokerProperties, true);
			return getRelyingPartyRegistration(oidcClient.get(), getIdentityProvider(), samlRp);
		}
		throw OidcExceptionHelper.createOidcException(OAuth2ErrorCodes.INVALID_REQUEST,
				String.format("No OIDC support for clientId=%s", registrationId), "client_id not supported");
	}

	private OidcIdentityProvider getIdentityProvider() {
		if (oidcProperties != null && oidcProperties.getIdentityProvider() != null) {
			return oidcProperties.getIdentityProvider();
		}
		throw OidcExceptionHelper.createOidcException(OAuth2ErrorCodes.SERVER_ERROR,
				"No OIDC support without a configured trustbroker.config.oidc.identityProvider", "OIDC not enabled");
	}

	// first we use explicitly configured Oidc.Client.federationId, if not set we use RelyingParty.id
	private static String pickFederationId(OidcClient client, RelyingParty relyingParty) {
		if (client.getFederationId() != null) {
			return client.getFederationId(); // override manually in Oidc.Client with federationId pointing to alias
		}
		else if (relyingParty != null && relyingParty.getUnaliasedId() != null) {
			return relyingParty.getUnaliasedId(); // pick our originating parent (default for reduced config)
		}
		else if (relyingParty != null && relyingParty.getId() != null) {
			return relyingParty.getId(); // pick our parent (default for reduced config)
		}
		return client.getId(); // fallback (should not happen)
	}

	private RelyingPartyRegistration getRelyingPartyRegistration(OidcClient client, OidcIdentityProvider identityProvider,
			RelyingParty relyingParty) {
		var oidcIdpCredential = relyingPartyDefinitions.getOidcIdpCredential();
		if (oidcIdpCredential == null) {
			throw OidcExceptionHelper.createOidcException(OAuth2ErrorCodes.SERVER_ERROR,
					"No OIDC support without a configured IDP credential", "OIDC not enabled");
		}

		var clientId = client.getId();
		var federationId = pickFederationId(client, relyingParty);
		return RelyingPartyRegistration.withRegistrationId(clientId)
				.entityId(federationId) // Request.Issuer value on SAML side should match our SAML setup wrapping N OIDC clients
				.signingX509Credentials(cred -> {
					Saml2X509Credential signing = oidcIdpCredential.getSigner();
					cred.add(signing);
				})
				// Validation
				.assertingPartyMetadata(details -> details
						// Must match with the incoming Response.Issuer
						.entityId(identityProvider.getResponseIssuerId())
						// Default is GET
						.singleSignOnServiceBinding(Saml2MessageBinding.POST)
						//Request.Destination
						.singleSignOnServiceLocation(identityProvider.getAssertionConsumerService())
						// Response.Assertion.Signature
						.verificationX509Credentials(cer -> cer.add(oidcIdpCredential.getTrust()))
				)
				.decryptionX509Credentials(c -> {
					if (signer != null) {
						c.add(getSaml2Credential(signer));
					}
				})
				.build();
	}

	private static Saml2X509Credential getSaml2Credential(Credential credential) {
		X509Certificate entityCertificate = ((X509Credential) credential).getEntityCertificate();

		return new Saml2X509Credential(credential.getPrivateKey(), entityCertificate,
				Saml2X509Credential.Saml2X509CredentialType.DECRYPTION);
	}

}
