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

package swiss.trustbroker.federation.service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.xml.SerializeSupport;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.AuthnAuthorityDescriptor;
import org.opensaml.saml.saml2.metadata.AuthnQueryService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.w3c.dom.Element;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.util.CredentialReader;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.util.ApiSupport;

@Service
@Slf4j
public class FederationMetadataService {

	private final TrustBrokerProperties trustBrokerProperties;

	private final RelyingPartySetupService relyingPartySetupService;

	private Credential signer;

	private List<Credential> allSigners;

	private List<Credential> cpDecryptionCredentials;

	FederationMetadataService(TrustBrokerProperties trustBrokerProperties, RelyingPartySetupService relyingPartySetupService) {
		this.trustBrokerProperties = trustBrokerProperties;
		this.relyingPartySetupService = relyingPartySetupService;
		// initialized onApplicationEvent
		this.signer = null;
		this.allSigners = null;
		this.cpDecryptionCredentials = null;
	}

	@EventListener(ContextRefreshedEvent.class)
	public void onApplicationEvent() {
		// signing
		signer = CredentialReader.createCredential(trustBrokerProperties.getSigner()); // sign
		log.info("Loaded active metaDataSignerTrust={}", trustBrokerProperties.getSigner().getSignerCert());
		allSigners = loadTrustableCerts(trustBrokerProperties.getRolloverSigner()); // trust

		// encryption
		cpDecryptionCredentials = relyingPartySetupService.getAllCpDecryptionCredentials();
	}

	private List<Credential> loadTrustableCerts(KeystoreProperties keystoreProperties) {
		var ret = new ArrayList<Credential>();
		ret.add(signer);
		// Support any number of rollover certs, our peers might be challenged though
		try {
			var file = new File(keystoreProperties.getSignerCert());
			if (file.exists()) {
				ret.addAll(CredentialReader.readTrustCredentials(
						keystoreProperties.getSignerCert(),
						keystoreProperties.getType(),
						keystoreProperties.getPassword(),
						keystoreProperties.getKeyEntryId()
				));
				log.info("Loaded rollover metaDataSignerTrust={} trustCount={}", keystoreProperties.getSignerCert(), ret.size());
			}
			else {
				log.info("No rollover metaDataSignerTrust={}", keystoreProperties.getSignerCert());
			}
		}
		catch (TechnicalException ex) {
			log.error("Rollover signer certificate loading from file={} failed with message={}",
					trustBrokerProperties.getRolloverSigner(), ex.getInternalMessage(), ex);
		}
		return ret;
	}

	public String getFederationMetadata(boolean idpSide, boolean spSide) {
		try {
			EntityDescriptor entityDescriptor = generateMetadata(idpSide, spSide);
			Element domDescriptor = SamlUtil.marshallMessage(entityDescriptor);
			SamlUtil.removeNewLinesFromCertificates(domDescriptor);
			return SerializeSupport.prettyPrintXML(domDescriptor);
		}
		catch (MessageEncodingException e) {
			throw new TechnicalException(String.format("Could not encode federation metadata ex=%s", e.getMessage()));
		}
	}

	public EntityDescriptor generateMetadata(boolean idpSide, boolean spSide) {
		EntityDescriptor descriptor = OpenSamlUtil.buildSamlObject(EntityDescriptor.class);
		UUID uuid = UUID.randomUUID();
		descriptor.setID("_" + uuid);
		descriptor.setEntityID(trustBrokerProperties.getIssuer());

		var idpDescriptor = buildIdpSsoDescriptor();
		if (idpDescriptor != null && idpSide) {
			descriptor.getRoleDescriptors().add(idpDescriptor);
		}

		var spDescriptor = buildSpSsoDescriptor();
		if (spDescriptor != null && spSide) {
			descriptor.getRoleDescriptors().add(spDescriptor);
		}

		var authnAuthorityDescriptor = buildAuthnAuthorityDescriptor();
		if (authnAuthorityDescriptor != null) {
			descriptor.getRoleDescriptors().add(authnAuthorityDescriptor);
		}

		// NOTE: Currently all signers use the same cert so the following is not really an issue but with multiple signers
		// We use sha256 default signing here to not worsen the problem by just picking an RYP setup for key material and config
		var signature = SamlFactory.prepareSignableObject(
				descriptor, signer, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, null, null);
		SamlUtil.signSamlObject(descriptor, signature);
		return descriptor;
	}

	protected IDPSSODescriptor buildIdpSsoDescriptor() {
		var samlConfig = trustBrokerProperties.getSaml();
		if (samlConfig == null || !samlConfig.isIdpMetadataEnabled()) {
			return null;
		}
		var consumerUrl = samlConfig.getConsumerUrl();
		var idpDescriptor = OpenSamlUtil.buildSamlObject(IDPSSODescriptor.class);
		idpDescriptor.setWantAuthnRequestsSigned(true);
		idpDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		for (var binding : samlConfig.getBindings()) {
			idpDescriptor.getSingleSignOnServices()
						 .add(getSingleSignOnService(consumerUrl, binding));
			if (samlConfig.isIdpLogoutMetadataEnabled()) {
				idpDescriptor.getSingleLogoutServices()
							 .add(getSingleLogoutService(consumerUrl, binding));
			}
			// artifact resolution is only for artifact binding:
			if (SamlBinding.ARTIFACT.is(binding) && samlConfig.getArtifactResolution() != null) {
				idpDescriptor.getArtifactResolutionServices()
							 .add(getArtifactResolutionService());
			}
		}
		for (String nameIdFormat : samlConfig.getIdpNameFormats()) {
			idpDescriptor.getNameIDFormats()
						 .add(getNameIdFormat(nameIdFormat));
		}
		if (allSigners != null) {
			allSigners.forEach(cred -> idpDescriptor.getKeyDescriptors().add(getKeyDescriptor(cred, UsageType.SIGNING)));
		}
		// Encryption certs towards RPs belong to IDP descriptor (matching the role of XTB towards RPs)
		return idpDescriptor;
	}

	private ArtifactResolutionService getArtifactResolutionService() {
		var artifactResolutionService = OpenSamlUtil.buildSamlObject(ArtifactResolutionService.class);
		artifactResolutionService.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
		artifactResolutionService.setLocation(trustBrokerProperties.getSaml().getArtifactResolution().getServiceUrl());
		artifactResolutionService.setIndex(trustBrokerProperties.getSaml().getArtifactResolution().getIndex());
		return artifactResolutionService;
	}

	private static NameIDFormat getNameIdFormat(String nameIdFormat) {
		NameIDFormat nameIDFormat = OpenSamlUtil.buildSamlObject(NameIDFormat.class);
		nameIDFormat.setURI(nameIdFormat);
		return nameIDFormat;
	}

	protected SPSSODescriptor buildSpSsoDescriptor() {
		var samlConfig = trustBrokerProperties.getSaml();
		if (samlConfig == null || !samlConfig.isSpMetadataEnabled()) {
			return null;
		}
		var consumerUrl = samlConfig.getConsumerUrl();
		var spDescriptor = OpenSamlUtil.buildSamlObject(SPSSODescriptor.class);
		spDescriptor.setAuthnRequestsSigned(true);
		spDescriptor.setWantAssertionsSigned(true);
		spDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		for (String binding : samlConfig.getBindings()) {
			var index = spDescriptor.getAssertionConsumerServices().size();
			spDescriptor.getAssertionConsumerServices().add(getAssertionConsumerService(consumerUrl, binding, index));
			if (samlConfig.isSpLogoutMetadataEnabled()) {
				spDescriptor.getSingleLogoutServices()
							.add(getSingleLogoutService(consumerUrl, binding));
			}
		}
		spDescriptor.getArtifactResolutionServices().add(getArtifactResolutionService());
		for (String nameIdFormat : samlConfig.getSpNameFormats()) {
			spDescriptor.getNameIDFormats().add(getNameIdFormat(nameIdFormat));
		}
		allSigners.forEach(cred -> spDescriptor.getKeyDescriptors().add(getKeyDescriptor(cred, UsageType.SIGNING)));
		// Encryption certs towards CPs belong to SP descriptor (matching the role of XTB towards CPs)
		if (!cpDecryptionCredentials.isEmpty()) {
			cpDecryptionCredentials.forEach(cred -> spDescriptor.getKeyDescriptors().add(getKeyDescriptor(cred, UsageType.ENCRYPTION)));
		}
		return spDescriptor;
	}

	private static KeyDescriptor getKeyDescriptor(Credential credential, UsageType usageType) {
		KeyDescriptor keyDescriptor = OpenSamlUtil.buildSamlObject(KeyDescriptor.class);
		KeyInfo keyInfo = SamlFactory.createKeyInfo(credential);
		keyDescriptor.setUse(usageType);
		keyDescriptor.setKeyInfo(keyInfo);
		return keyDescriptor;
	}

	private static SingleSignOnService getSingleSignOnService(String location, String binding) {
		SingleSignOnService sso = OpenSamlUtil.buildSamlObject(SingleSignOnService.class);
		sso.setLocation(location);
		sso.setBinding(binding);
		return sso;
	}

	private static SingleLogoutService getSingleLogoutService(String location, String binding) {
		SingleLogoutService sso = OpenSamlUtil.buildSamlObject(SingleLogoutService.class);
		sso.setLocation(location);
		sso.setBinding(binding);
		return sso;
	}

	private static AssertionConsumerService getAssertionConsumerService(String location, String binding, int index) {
		AssertionConsumerService assertionConsumerService = OpenSamlUtil.buildSamlObject(AssertionConsumerService.class);
		assertionConsumerService.setLocation(location);
		assertionConsumerService.setBinding(binding);
		assertionConsumerService.setIndex(index);
		return assertionConsumerService;
	}

	private AuthnAuthorityDescriptor buildAuthnAuthorityDescriptor() {
		if (trustBrokerProperties.getWstrust() == null || !trustBrokerProperties.getWstrust().isEnabled()) {
			return null;
		}
		AuthnAuthorityDescriptor authnAuthorityDescriptor = OpenSamlUtil.buildSamlObject(AuthnAuthorityDescriptor.class);
		authnAuthorityDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		authnAuthorityDescriptor.getAuthnQueryServices().add(getAuthnQueryService());
		return authnAuthorityDescriptor;
	}

	private AuthnQueryService getAuthnQueryService() {
		AuthnQueryService authnQueryService = OpenSamlUtil.buildSamlObject(AuthnQueryService.class);
		authnQueryService.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
		String perimeterUrl = trustBrokerProperties.getPerimeterUrl();
		authnQueryService.setLocation(perimeterUrl + ApiSupport.ADFS_WS_TRUST_COMPAT_URL);
		return authnQueryService;
	}

}
