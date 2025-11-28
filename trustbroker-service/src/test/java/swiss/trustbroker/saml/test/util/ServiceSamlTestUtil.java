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

package swiss.trustbroker.saml.test.util;

import static swiss.trustbroker.config.TestConstants.CACHE_DEFINITION_PATH;
import static swiss.trustbroker.config.TestConstants.LATEST_DEFINITION_PATH;
import static swiss.trustbroker.config.TestConstants.TEST_BASE_PROFILE;
import static swiss.trustbroker.config.TestConstants.TEST_BASE_STANDARD;
import static swiss.trustbroker.config.TestConstants.TEST_CP_DEFINITIONS;
import static swiss.trustbroker.config.TestConstants.TEST_SETUP_CP;
import static swiss.trustbroker.config.TestConstants.TEST_SETUP_RP;
import static swiss.trustbroker.config.TestConstants.TEST_SSO_GROUP_SETUP;

import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.EncryptionConfiguration;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.mock.web.MockHttpServletRequest;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderDefinitions;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.federation.xmlconfig.SsoGroupSetup;
import swiss.trustbroker.homerealmdiscovery.util.ClaimsProviderUtil;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;
import swiss.trustbroker.sessioncache.dto.Lifecycle;
import swiss.trustbroker.sessioncache.dto.LifecycleState;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.test.saml.util.SamlHttpTestBase;
import swiss.trustbroker.test.saml.util.SamlTestBase;

public class ServiceSamlTestUtil implements SamlHttpTestBase {

	private static final String TEST_AUTHN_REQUEST = LATEST_DEFINITION_PATH + "RPToTBAuthnRequest.xml";

	private static final String TEST_AUTHN_RESPONSE = LATEST_DEFINITION_PATH + "CPToTBAuthnResponse.xml";

	private static final String TEST_LOGOUT_REQUEST = LATEST_DEFINITION_PATH + "LogoutRequest.xml";

	private static final String SAMPLE_CP_RESPONSE = LATEST_DEFINITION_PATH + "SampleCPResponse.xml";

	private static final String TEST_LOGOUT_RESPONSE = LATEST_DEFINITION_PATH + "LogoutResponse.xml";

	public static final String AUTHN_REQUEST_ISSUER_ID = "urn:test:TESTRP";


	public static AuthnRequest loadAuthnRequest() {
		String authnRequestFilePath = SamlTestBase.filePathFromClassPath(TEST_AUTHN_REQUEST);
		return SamlIoUtil.unmarshallAuthnRequest(authnRequestFilePath);
	}

	public static Response loadAuthnResponse() {
		String authnRequestFilePath = SamlTestBase.filePathFromClassPath(TEST_AUTHN_RESPONSE);
		return SamlIoUtil.unmarshallResponse(authnRequestFilePath);
	}

	public static LogoutRequest loadLogoutRequest() {
		String logoutRequestFilePath = SamlTestBase.filePathFromClassPath(TEST_LOGOUT_REQUEST);
		return SamlIoUtil.unmarshallLogoutRequest(logoutRequestFilePath);
	}

	public static SAMLObject loadSampleResponse() {
		String authResponseFilePath = SamlTestBase.filePathFromClassPath(SAMPLE_CP_RESPONSE);
		return (SAMLObject) SamlIoUtil.getXmlObjectFromFileOrClassPath(authResponseFilePath);
	}


	public static LogoutResponse loadLogoutResponse() {
		String logoutRequestFilePath = SamlTestBase.filePathFromClassPath(TEST_LOGOUT_RESPONSE);
		return SamlIoUtil.unmarshallLogoutResponse(logoutRequestFilePath);
	}

	public static RelyingPartySetup loadBaseClaimMergeTest() {
		List<RelyingParty> relyingParties = loadRelyingParties();
		RelyingPartySetup rulesDefinitions = RelyingPartySetup.builder().relyingParties(relyingParties).build();
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		String definitionPath = getBaseRuleFilePath();
		RelyingPartySetupUtil.loadRelyingParty(relyingParties, definitionPath,
				CACHE_DEFINITION_PATH, null, Collections.emptyList(), null, claimsProviderSetup, null);
		Credential credential = SamlTestBase.dummyCredential(
				SamlTestBase.TEST_TB_KEYSTORE_JKS,
				SamlTestBase.TEST_KEYSTORE_PW,
				SamlTestBase.TEST_KEYSTORE_TB_ALIAS);
		for (RelyingParty relyingParty : relyingParties) {
			relyingParty.setRpSigner(credential);
			relyingParty.setRpTrustCredentials(List.of(credential));
			if (relyingParty.getAcWhitelist() != null) {
				relyingParty.getAcWhitelist().calculateDerivedUrls();
			}
		}
		return rulesDefinitions;
	}

	public static List<RelyingParty> loadRelyingParties() {
		return loadRelyingPartySetup().getRelyingParties();
	}

	public static RelyingPartySetup loadRelyingPartySetup() {
		String ruleDefinition = SamlTestBase.filePathFromClassPath(TEST_SETUP_RP);
		return ClaimsProviderUtil.loadRelyingPartySetup(ruleDefinition);
	}

	public static ClaimsProviderDefinitions loadClaimsProviderDefinitions() {
		String claimsProvider = SamlTestBase.filePathFromClassPath(TEST_CP_DEFINITIONS);
		return ClaimsProviderUtil.loadClaimsProviderDefinitions(claimsProvider);
	}

	public static SsoGroupSetup loadSsoGroups() {
		String ssoGroups = SamlTestBase.filePathFromClassPath(TEST_SSO_GROUP_SETUP);
		return ClaimsProviderUtil.loadSsoGroups(ssoGroups);
	}

	public static String getBaseRuleFilePath() {
		String file = SamlTestBase.filePathFromClassPath(TEST_BASE_STANDARD);
		int filenNameStartIndex = file.indexOf(TEST_BASE_PROFILE);
		return file.substring(0, filenNameStartIndex);
	}

	public static Signature givenSignature(String certFileName, String password, String alias) {

		Signature signature = OpenSamlUtil.buildSamlObject(Signature.class);
		signature.setSigningCredential(SamlTestBase.dummyCredential(certFileName, password, alias));
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		signature.setSchemaLocation("http://www.w3.org/2000/09/xmldsig#");
		signature.setKeyInfo(createMockKeyInfo(SamlTestBase.dummyCredential(certFileName, password, alias)));

		return signature;
	}


	public static KeyInfo createMockKeyInfo(Credential credential) {
		EncryptionConfiguration secConfiguration = SecurityConfigurationSupport.getGlobalEncryptionConfiguration();
		NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager = secConfiguration.getDataKeyInfoGeneratorManager();
		if (namedKeyInfoGeneratorManager == null) {
			throw new TechnicalException("NamedKeyInfoGeneratorManager is null");
		}
		KeyInfoGeneratorManager keyInfoGeneratorManager = namedKeyInfoGeneratorManager.getDefaultManager();
		KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(credential);
		if (keyInfoGeneratorFactory == null) {
			throw new TechnicalException("KeyInfoGeneratorFactory is null");
		}
		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
		KeyInfo keyInfo = null;
		try {
			keyInfo = keyInfoGenerator.generate(credential);
			return keyInfo;
		}
		catch (SecurityException e) {
			throw new TechnicalException(String.format("Key generation exception: %s", e.getMessage()));
		}
	}

	public static String getResourceDir() {
		String file = SamlTestBase.filePathFromClassPath(TEST_BASE_STANDARD);
		int filenNameStartIndex = file.indexOf(TEST_BASE_STANDARD);
		return file.substring(0, filenNameStartIndex);
	}

	public static StateData givenStateCacheData() {
		OffsetDateTime now = OffsetDateTime.now();

		StateData spStateData = StateData.builder()
				.lifecycle(Lifecycle.builder().lifecycleState(LifecycleState.INIT).build())
				.id("sp-requestid")
				.issuer(AUTHN_REQUEST_ISSUER_ID)
				.relayState("sp-relaystate")
				.build();
		return StateData.builder()
				.lifecycle(Lifecycle.builder().lifecycleState(LifecycleState.INIT).build())
				.id("idp-requestid")
				.issuer("urn:test:TESTCP")
				.relayState("idp-relay-state")
				.issueInstant(now.toString())
				.spStateData(spStateData)
				.build();
	}

	public static StateData givenInvalidStateCache() {
		return StateData.builder()
				.id("requestid")
				.build();
	}

	public static SecurityChecks givenEnabledSecurity() {
		SecurityChecks securityChecks = new SecurityChecks();
		securityChecks.setValidateAuthnRequest(true);
		securityChecks.setValidateResponseIssuer(true);
		securityChecks.setValidateSecurityTokenRequest(true);
		securityChecks.setRequireSignedResponse(false);
		return securityChecks;
	}

	public static ClaimsProviderSetup loadClaimsProviderSetup() {
		String claimSetup = SamlTestBase.filePathFromClassPath(TEST_SETUP_CP);
		ClaimsProviderSetup claimsProviderSetup = ClaimsProviderUtil.loadClaimsProviderSetup(claimSetup);
		Credential credential = SamlTestBase.dummyCredential(
				SamlTestBase.TEST_TB_KEYSTORE_JKS,
				SamlTestBase.TEST_KEYSTORE_PW,
				SamlTestBase.TEST_KEYSTORE_TB_ALIAS);
		for (ClaimsParty claimsParty : claimsProviderSetup.getClaimsParties()) {
			claimsParty.setCpTrustCredential(List.of(credential));
		}
		return claimsProviderSetup;
	}

	@Override
	public HttpServletRequest buildHttpRequestForSamlString(String httpMethod, String requestUri,
			Map<String, String[]> parameters) {
		var request = new MockHttpServletRequest();
		request.setMethod(httpMethod);
		request.setRequestURI(requestUri);
		request.setParameters(parameters);
		return request;
	}
}
