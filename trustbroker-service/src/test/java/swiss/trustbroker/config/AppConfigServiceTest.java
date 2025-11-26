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

package swiss.trustbroker.config;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static swiss.trustbroker.config.TestConstants.LATEST_INVALID_DEFINITION_PATH;

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.setup.service.GitService;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.service.XmlConfigStatusService;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.FeatureEnum;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.federation.xmlconfig.Sso;
import swiss.trustbroker.federation.xmlconfig.SsoGroup;
import swiss.trustbroker.federation.xmlconfig.SsoGroupSetup;
import swiss.trustbroker.homerealmdiscovery.service.WebResourceProvider;
import swiss.trustbroker.homerealmdiscovery.util.ClaimsProviderUtil;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;
import swiss.trustbroker.metrics.service.MetricsService;
import swiss.trustbroker.oidc.ClientConfigInMemoryRepository;
import swiss.trustbroker.oidc.OidcEncryptionKeystoreService;
import swiss.trustbroker.oidc.cache.service.OidcMetadataCacheService;
import swiss.trustbroker.script.service.ScriptService;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = { AppConfigService.class })
class AppConfigServiceTest {

	@MockitoBean
	private ApplicationEventPublisher eventPublisher;

	@MockitoBean
	private TrustBrokerProperties properties;

	@MockitoBean
	private GitService gitService;

	@MockitoBean
	private RelyingPartyDefinitions relyingPartyDefinitions;

	@MockitoBean
	private ScriptService scriptService;

	@MockitoBean
	private ClientConfigInMemoryRepository clientConfigInMemoryRepository;

	@MockitoBean
	private MetricsService metricsService;

	@MockitoBean
	private XmlConfigStatusService xmlConfigStatusService;

	@MockitoBean
	private OidcMetadataCacheService oidcMetadataCacheService;

	@MockitoBean
	private WebResourceProvider resourceProvider;

	@MockitoBean
	private CredentialService credentialService;

	@MockitoBean
	private OidcEncryptionKeystoreService oidcEncryptionKeystoreService;

	@Autowired
	private AppConfigService appConfigService;

	@Test
	void TestCheckRpSsoIntegrity() {
		var ssoGroup = SsoGroup.builder().name("sso1").build();
		var rpOk = RelyingParty.builder()
							   .id("rp3")
							   .sso(Sso.builder().enabled(true).groupName(ssoGroup.getName()).build())
							   .build();
		var rpUnknownSsoGroup = RelyingParty.builder()
											.id("rp1")
											.sso(Sso.builder().enabled(true).groupName("unknown").build())
											.build();
		var rpMissingSsoGroup = RelyingParty.builder()
											.id("rp2")
											.sso(Sso.builder().enabled(true).build())
											.build();
		var rpSetup = RelyingPartySetup.builder().relyingParties(List.of(rpOk, rpMissingSsoGroup, rpUnknownSsoGroup)).build();
		var ssoSetup = SsoGroupSetup.builder().ssoGroups(List.of(ssoGroup)).build();

		AppConfigService.checkRpSsoIntegrity(rpSetup, ssoSetup);

		assertThat(rpOk.isValid(), is(true));
		assertThat(rpOk.getValidationStatus().getErrors(), hasSize(0));
		assertThat(rpUnknownSsoGroup.isValid(), is(true));
		assertThat(rpUnknownSsoGroup.getValidationStatus().getErrors(), hasSize(1));
		assertThat(rpMissingSsoGroup.isValid(), is(true));
		assertThat(rpMissingSsoGroup.getValidationStatus().getErrors(), hasSize(1));
	}

	@Test
	void testInvalidBase() {
		var relyingPartySetup = loadRelyingParty("SetupRPInvalidBase.xml");
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		assertDoesNotThrow(() ->
				RelyingPartySetupUtil.loadRelyingParty(
						relyingPartySetup.getRelyingParties(), LATEST_INVALID_DEFINITION_PATH, LATEST_INVALID_DEFINITION_PATH,
						properties, Collections.emptyList(), scriptService, claimsProviderSetup, null));
		var rp = relyingPartySetup.getRelyingParties().get(0);
		assertEquals(FeatureEnum.INVALID, rp.getEnabled());
	}

	@Test
	void loadConfigFromFileInvalidFile() {
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		var relyingPartySetup = loadRelyingParty("SetupRPInvalidCert.xml");
		doThrow(TechnicalException.class).when(credentialService).checkAndLoadCert(any(), any(), any());
		assertDoesNotThrow(() ->
				RelyingPartySetupUtil.loadRelyingParty(
						relyingPartySetup.getRelyingParties(), LATEST_INVALID_DEFINITION_PATH, LATEST_INVALID_DEFINITION_PATH,
						properties, Collections.emptyList(), scriptService, claimsProviderSetup, null));
		var rp = relyingPartySetup.getRelyingParties().get(0);
		// after RelyingPartySetupUtils validation, it is still valid
		assertEquals(FeatureEnum.TRUE, rp.getEnabled());
		appConfigService.checkAndLoadRelyingPartyCertificates(relyingPartySetup);
		assertEquals(FeatureEnum.INVALID, rp.getEnabled());
	}

	private RelyingPartySetup loadRelyingParty(String fileName) {
		var file = SamlTestBase.fileFromClassPath(LATEST_INVALID_DEFINITION_PATH + fileName);
		var relyingPartySetup = ClaimsProviderUtil.loadRelyingPartySetup(file);
		assertThat(relyingPartySetup.getRelyingParties(), hasSize(1));
		var rp = relyingPartySetup.getRelyingParties().get(0);
		// after loading, it is still valid
		assertEquals(FeatureEnum.TRUE, rp.getEnabled());
		return relyingPartySetup;
	}
}
