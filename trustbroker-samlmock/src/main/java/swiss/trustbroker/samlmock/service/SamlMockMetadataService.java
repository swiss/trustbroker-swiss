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

package swiss.trustbroker.samlmock.service;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.stereotype.Component;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.samlmock.SamlMockProperties;

@Component
@AllArgsConstructor
@Slf4j
public class SamlMockMetadataService {

	private static final List<String> SUPPORTED_SAML_BINDINGS = List.of(
			SAMLConstants.SAML2_POST_BINDING_URI,
			SAMLConstants.SAML2_REDIRECT_BINDING_URI,
			SAMLConstants.SAML2_ARTIFACT_BINDING_URI);

	private final SamlMockProperties properties;

	private final SamlMockFileService fileService;

	public EntityDescriptor generateMetadata() {
		EntityDescriptor descriptor = OpenSamlUtil.buildSamlObject(EntityDescriptor.class);
		descriptor.setID(buildSourceId());
		descriptor.setEntityID(properties.getArtifactResolutionIssuer());

		var idpSsoDescriptor = buildIdpSsoDescriptor();
		idpSsoDescriptor.getKeyDescriptors()
						.add(getKeyDescriptor(fileService.getResponseCredential(), UsageType.SIGNING));
		idpSsoDescriptor.getKeyDescriptors()
						.add(getKeyDescriptor(fileService.getEncryptionCredential(), UsageType.ENCRYPTION));
		descriptor.getRoleDescriptors()
				  .add(idpSsoDescriptor);
		var spSsoDescriptor = buildSpSsoDescriptor();
		spSsoDescriptor.getKeyDescriptors()
					   .add(getKeyDescriptor(fileService.getAuthnRequestCredential(), UsageType.SIGNING));
		spSsoDescriptor.getKeyDescriptors()
					   .add(getKeyDescriptor(fileService.getEncryptionCredential(), UsageType.ENCRYPTION));
		descriptor.getRoleDescriptors()
				  .add(spSsoDescriptor);

		var credential = fileService.getResponseCredential(); // re-use response signer for metadata
		var signature = SamlFactory.prepareSignableObject(
				descriptor, credential, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256, null, null);
		SamlUtil.signSamlObject(descriptor, signature);
		return descriptor;
	}

	private static KeyDescriptor getKeyDescriptor(Credential credential, UsageType usageType) {
		KeyDescriptor keyDescriptor = OpenSamlUtil.buildSamlObject(KeyDescriptor.class);
		KeyInfo keyInfo = SamlFactory.createKeyInfo(credential);
		keyDescriptor.setUse(usageType);
		keyDescriptor.setKeyInfo(keyInfo);
		return keyDescriptor;
	}

	private String buildSourceId() {
		var arIssuer = properties.getArtifactResolutionIssuer();
		if (arIssuer == null) {
			log.error("Missing artifactResolutionIssuer in config");
			throw new TechnicalException("Missing artifactResolutionIssuer in config");
		}
		return OpenSamlUtil.calculateArtifactSourceIdFromIssuerId(arIssuer);
	}

	private IDPSSODescriptor buildIdpSsoDescriptor() {
		IDPSSODescriptor idpDescriptor = OpenSamlUtil.buildSamlObject(IDPSSODescriptor.class);
		idpDescriptor.setWantAuthnRequestsSigned(true);
		idpDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
		var artifactResolutionService = buildArtifactResolutionService();
		idpDescriptor.getArtifactResolutionServices()
					 .add(artifactResolutionService);
		for (String binding : SUPPORTED_SAML_BINDINGS) {
			idpDescriptor.getSingleLogoutServices()
						 .add(getSingleLogoutService(properties.getIdpServiceUrl(), binding));
			idpDescriptor.getSingleSignOnServices()
						 .add(getSingleSignOnService(properties.getIdpServiceUrl(), binding));
		}
		return idpDescriptor;
	}

	public ArtifactResolutionService buildArtifactResolutionService() {
		var artifactResolutionService = OpenSamlUtil.buildSamlObject(ArtifactResolutionService.class);
		artifactResolutionService.setBinding(SAMLConstants.SAML2_SOAP11_BINDING_URI);
		artifactResolutionService.setLocation(properties.getArtifactResolutionServiceUrl());
		artifactResolutionService.setIndex(SamlMockConstants.ENDPOINT_INDEX);
		return artifactResolutionService;
	}

	private SPSSODescriptor buildSpSsoDescriptor() {
		var spssoDescriptor = OpenSamlUtil.buildSamlObject(SPSSODescriptor.class);
		spssoDescriptor.setAuthnRequestsSigned(true);
		spssoDescriptor.setWantAssertionsSigned(true);
		spssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

		for (String binding : SUPPORTED_SAML_BINDINGS) {
			spssoDescriptor.getSingleLogoutServices()
						   .add(getSingleLogoutService(properties.getAssertionConsumerServiceUrl(), binding));
			var index = spssoDescriptor.getAssertionConsumerServices().size();
			spssoDescriptor.getAssertionConsumerServices()
						   .add(getAssertionConsumerService(properties.getAssertionConsumerServiceUrl(), binding, index));
		}
		return spssoDescriptor;
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

}
