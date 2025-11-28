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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.metadata.ArtifactResolutionService;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.ArtifactResolution;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.config.dto.WsTrustConfig;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.test.saml.util.SamlTestBase;
import swiss.trustbroker.util.ApiSupport;

class FederationMetadataServiceTest {

	private static final String CONSUMER_URL = "https://localhost/acs";

	private static final String PERIMETER_URL = "https://localhost/perimeter";

	private static final String ARP_URL = "https://localhost/arp";

	private static final int ARP_INDEX = 1;

	private FederationMetadataService federationMetadataService;

	@BeforeAll
	static void init() {
		SamlInitializer.initSamlSubSystem();
	}

	@BeforeEach
	void setUp() {
		var trustBrokerProperties = givenProperties();
		var relyingPartySetupService = givenRpSetupService(trustBrokerProperties);
		federationMetadataService = new FederationMetadataService(trustBrokerProperties, relyingPartySetupService);
		federationMetadataService.onApplicationEvent(); // final application context
	}

	private RelyingPartySetupService givenRpSetupService(TrustBrokerProperties trustBrokerProperties) {
		var relyingPartiesMapping = new RelyingPartyDefinitions();

		var claimsParty = ClaimsParty.builder()
				.cpDecryptionCredentials(List.of(SamlTestBase.dummyCredential()))
				.build();

		List<ClaimsParty> claimParties = new ArrayList<>();
		claimParties.add(claimsParty);

		var claimsProviderSetup = ClaimsProviderSetup.builder()
				.claimsParties(claimParties)
				.build();

		relyingPartiesMapping.setClaimsProviderSetup(claimsProviderSetup);

		List<RelyingParty> relyingParties = new ArrayList<>();
		var relyingParty = RelyingParty.builder()
				.rpEncryptionTrustCredential(SamlTestBase.dummyCredential()) // does not affect metadata
				.build();
		relyingParties.add(relyingParty);

		var relyingPartySetup = RelyingPartySetup.builder()
				.relyingParties(relyingParties)
				.build();
		relyingPartiesMapping.setRelyingPartySetup(relyingPartySetup);
		return new RelyingPartySetupService(relyingPartiesMapping, trustBrokerProperties, Collections.emptyList());
	}

	private static TrustBrokerProperties givenProperties() {
		var trustBrokerProperties = new TrustBrokerProperties();
		var signer = new KeystoreProperties();
		trustBrokerProperties.setSigner(signer);
		trustBrokerProperties.setRolloverSigner(signer);
		signer.setSignerCert(SamlTestBase.filePathFromClassPath(SamlTestBase.X509_RSAENC_JKS));
		signer.setPassword(SamlTestBase.X509_RSAENC_PW);
		signer.setKeyEntryId(SamlTestBase.X509_RSAENC_ALIAS);
		trustBrokerProperties.setRolloverSigner(signer);
		var ar = new ArtifactResolution();
		ar.setServiceUrl(ARP_URL);
		ar.setIndex(ARP_INDEX);
		var saml = new SamlProperties();
		saml.setConsumerUrl(CONSUMER_URL);
		saml.setArtifactResolution(ar);
		trustBrokerProperties.setSaml(saml);
		trustBrokerProperties.setPerimeterUrl(PERIMETER_URL);
		var wsTrust = new WsTrustConfig();
		wsTrust.setWsBasePath(ApiSupport.WSTRUST_API);
		trustBrokerProperties.setWstrust(wsTrust);
		return trustBrokerProperties;
	}

	@Test
	void getFederationMetadata() {
		var result = federationMetadataService.getFederationMetadata(true, true);
		assertThat(result, is(not(nullValue())));
		var samlObj = SamlIoUtil.getXmlObjectFromStream(
				new ByteArrayInputStream(result.getBytes(StandardCharsets.UTF_8)), "test");
		assertThat(samlObj, is(instanceOf(EntityDescriptor.class)));
		var entityDescriptor = (EntityDescriptor) samlObj;
		assertThat(entityDescriptor.isSigned(), is(true));
		validateIdp(entityDescriptor);
		validateSp(entityDescriptor);
		// AuthnAuthority
		var authDescriptor = entityDescriptor.getAuthnAuthorityDescriptor(SAMLConstants.SAML20P_NS);
		assertThat(authDescriptor, is(not(nullValue())));
		var authServices = authDescriptor.getAuthnQueryServices();
		validateLocation(authServices, PERIMETER_URL + ApiSupport.ADFS_WS_TRUST_COMPAT_URL);
		validateBinding(authServices, SAMLConstants.SAML2_SOAP11_BINDING_URI, true);
	}

	private void validateIdp(EntityDescriptor entityDescriptor) {
		var idpSsoDescriptor = entityDescriptor.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
		assertThat(idpSsoDescriptor, is(not(nullValue())));
		assertThat(idpSsoDescriptor.getWantAuthnRequestsSigned(), is(true));
		assertThat(idpSsoDescriptor.getSupportedProtocols(), contains(SAMLConstants.SAML20P_NS));
		validateNameIdFormats(idpSsoDescriptor.getNameIDFormats());
		// SSO
		var ssoServices = idpSsoDescriptor.getSingleSignOnServices();
		validateLocation(ssoServices, CONSUMER_URL);
		validateBindings(ssoServices, true);
		// SLO
		var sloServices = idpSsoDescriptor.getSingleLogoutServices();
		validateLocation(sloServices, CONSUMER_URL);
		validateBindings(sloServices, true);
		// ARP
		var arpServices = idpSsoDescriptor.getArtifactResolutionServices();
		validateLocation(arpServices, ARP_URL);
		validateArpIndexes(arpServices, ARP_INDEX);
		validateBinding(arpServices, SAMLConstants.SAML2_SOAP11_BINDING_URI, true);
		// KeyDescriptor
		validateKeyDescriptor(idpSsoDescriptor.getKeyDescriptors(), 2);
	}

	private void validateSp(EntityDescriptor entityDescriptor) {
		var spSsoDescriptor = entityDescriptor.getSPSSODescriptor(SAMLConstants.SAML20P_NS);
		assertThat(spSsoDescriptor, is(not(nullValue())));
		assertThat(spSsoDescriptor.getWantAssertionsSigned(), is(true));
		assertThat(spSsoDescriptor.isAuthnRequestsSigned(), is(true));
		assertThat(spSsoDescriptor.getSupportedProtocols(), contains(SAMLConstants.SAML20P_NS));
		validateNameIdFormats(spSsoDescriptor.getNameIDFormats());
		// ACS
		var acsServices = spSsoDescriptor.getAssertionConsumerServices();
		validateLocation(acsServices, CONSUMER_URL);
		validateBindings(acsServices, true);
		// SLO
		var spSloServices = spSsoDescriptor.getSingleLogoutServices();
		validateLocation(spSloServices, CONSUMER_URL);
		validateBindings(spSloServices, false);
		// KeyDescriptors
		validateKeyDescriptor(spSsoDescriptor.getKeyDescriptors(), 3);
	}

	private static void validateNameIdFormats(List<NameIDFormat> nameIDFormats) {
		var props = new SamlProperties();
		assertThat(nameIDFormats.stream().map(NameIDFormat::getURI).toList(),
				is(props.getIdpNameFormats()));
	}

	private static void validateBindings(List<? extends Endpoint> services, boolean present) {
		var props = new SamlProperties();
		for (String binding : props.getBindings()) {
			validateBinding(services, binding, present);
		}
	}

	private static void validateBinding(List<? extends Endpoint> services, String binding, boolean present) {
		assertThat(services.stream().anyMatch(svc -> binding.equals(svc.getBinding())), is(present));
	}

	private static void validateLocation(List<? extends Endpoint> services, String location) {
		for (var service : services) {
			assertThat(service.getLocation(), is(location));
		}
	}

	private static void validateArpIndexes(List<? extends ArtifactResolutionService> services, int index) {
		for (var service : services) {
			assertThat(service.getIndex(), is(index));
		}
	}

	private static void validateKeyDescriptor(List<KeyDescriptor> keyDescriptors, int expectedKeyDescriptors) {
		assertThat(keyDescriptors, hasSize(expectedKeyDescriptors));
		for (var keyDescriptor : keyDescriptors) {
			assertThat(keyDescriptor.getKeyInfo(), is(not(nullValue())));
			assertThat(keyDescriptor.getUse(), is(not(nullValue())));
		}
	}

}
