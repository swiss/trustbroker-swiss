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

package swiss.trustbroker.homerealmdiscovery.util;

import static org.hamcrest.CoreMatchers.endsWith;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static swiss.trustbroker.config.TestConstants.CACHE_DEFINITION_PATH;
import static swiss.trustbroker.config.TestConstants.CACHE_PATH;
import static swiss.trustbroker.config.TestConstants.TEST_BASE_PROFILE;
import static swiss.trustbroker.config.TestConstants.TEST_BASE_STANDARD;
import static swiss.trustbroker.config.TestConstants.TEST_CACHE_BASE_RULE;
import static swiss.trustbroker.config.TestConstants.TEST_RULE_WITH_CACHE_BASE_DEFINITIONS;
import static swiss.trustbroker.config.TestConstants.TEST_SETUP_CP;
import static swiss.trustbroker.config.TestConstants.TEST_SETUP_RP;
import static swiss.trustbroker.config.TestConstants.TEST_SETUP_RP_INVALID_XML;

import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmRequests;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.api.idm.service.IdmStatusPolicyCallback;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.config.TestConstants;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.AcWhitelist;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.Certificates;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ClaimsProviderSetup;
import swiss.trustbroker.federation.xmlconfig.ConstAttributes;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.FeatureEnum;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.Oidc;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.RelyingPartySetup;
import swiss.trustbroker.federation.xmlconfig.Script;
import swiss.trustbroker.federation.xmlconfig.Scripts;
import swiss.trustbroker.federation.xmlconfig.SignerKeystore;
import swiss.trustbroker.federation.xmlconfig.SignerTruststore;
import swiss.trustbroker.script.service.ScriptService;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.STRICT_STUBS)
class RuleDefinitionUtilTest {

	private static class SortingIdmService implements IdmQueryService {

		@Override
		public Optional<IdmResult> getAttributes(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse,
				IdmRequests idmRequests, IdmStatusPolicyCallback statusPolicyCallback) {
			return Optional.empty();
		}

		@Override
		public List<IdmRequest> sortIdmRequests(IdmRequests idmRequests) {
			return idmRequests.getQueryList().stream()
					.sorted(Comparator.comparing(IdmRequest::getName))
					.toList();
		}
	}


	private static final String IDENTITY_QUERY = "IDENTITY";

	private static final String TENANT_QUERY = "TENANT";

	private static final String GLOBAL_QUERY = "GLOBAL";

	private final IdmQueryService idmQueryService = new SortingIdmService();

	@MockitoBean
	private ScriptService scriptService;

	@Test
	void joinAndDistinctDefinitionsEmptyTest() {
		List<Definition> attributeList = null;
		List<Definition> baseAttribute = null;
		List<Definition> result = RelyingPartySetupUtil.joinAndDistinctDefinitions(attributeList, baseAttribute);

		assertTrue(result.isEmpty());

		baseAttribute = givenAttributeLists();
		result = RelyingPartySetupUtil.joinAndDistinctDefinitions(attributeList, baseAttribute);

		assertEquals(result, baseAttribute);

		attributeList = givenAttributeLists();
		baseAttribute = Collections.emptyList();
		result = RelyingPartySetupUtil.joinAndDistinctDefinitions(attributeList, baseAttribute);

		assertEquals(result, attributeList);
	}

	@Test
	void joinAndDistinctDefinitionsNoBaseTest() {
		List<Definition> attributeList = givenAttributeLists();
		List<Definition> baseAttribute = null;
		List<Definition> result = RelyingPartySetupUtil.joinAndDistinctDefinitions(attributeList, baseAttribute);

		assertEquals(result, attributeList);

		baseAttribute = new ArrayList<>();
		result = RelyingPartySetupUtil.joinAndDistinctLists(attributeList, baseAttribute);

		assertEquals(result, attributeList);
	}

	@Test
	void joinAndDistinctDefinitionsDistinctTest() {
		List<Definition> attributeList = givenAttributeDuplicatesWithBaseLists();
		int attributeListSize = attributeList.size();
		List<Definition> baseAttribute = givenBaseAttributeList();

		List<Definition> result = RelyingPartySetupUtil.joinAndDistinctDefinitions(attributeList, baseAttribute);
		List<Definition> firstNames = result.stream().filter(s -> s.getName().equals("FirstName")).toList();

		assertEquals(attributeListSize + baseAttribute.size() - 1, result.size());
		assertEquals(1, firstNames.size());
	}

	@Test
	void joinAndDistinctListTest() {
		List<String> acWhiteListDuplicates = givenAcWhiteListDuplicatesWithBaseLists();
		int attributeListSize = acWhiteListDuplicates.size();
		List<String> baseAcWhiteList = givenBaseAcWhiteListList();

		List<String> result = RelyingPartySetupUtil.joinAndDistinctLists(acWhiteListDuplicates, baseAcWhiteList);
		List<String> acList = result.stream().filter(s -> s.equals("http://test.sp1.trustbroker.swiss")).toList();

		assertEquals(attributeListSize + baseAcWhiteList.size() - 1, result.size());
		assertEquals(1, acList.size());
	}


	@Test
	void joinAndDistinctDefinitionsTest() {
		List<Definition> attributeList = givenAttributeLists();
		List<Definition> baseAttribute = givenBaseAttributeList();
		List<Definition> result = RelyingPartySetupUtil.joinAndDistinctDefinitions(attributeList, baseAttribute);

		assertTrue(result.contains(baseAttribute.get(0)));
	}

	@Test
	void getExistingClaimNoResultTest() {
		IdmLookup idmLookup = givenIdmLookup();
		IdmQuery existingClaim = RelyingPartySetupUtil.getExistingIdmQuery(idmLookup, TENANT_QUERY, null);

		assertNull(existingClaim);
	}

	@Test
	void getExistingClaimFoundClaimTest() {
		IdmLookup idmLookup = givenIdmLookup();
		IdmQuery existingClaim = RelyingPartySetupUtil.getExistingIdmQuery(idmLookup, IDENTITY_QUERY, null);

		assertNotNull(existingClaim);
	}

	@Test
	void getExistingClaimNullQueryTest() {
		IdmLookup idmLookup = givenIdmLookupWithNullQuery();
		IdmQuery existingClaim = RelyingPartySetupUtil.getExistingIdmQuery(idmLookup, IDENTITY_QUERY, null);

		assertNull(existingClaim);
	}

	@Test
	void getExistingClaimNullLookupTest() {
		IdmQuery existingClaim = RelyingPartySetupUtil.getExistingIdmQuery(null, IDENTITY_QUERY, null);

		assertNull(existingClaim);
	}

	@Test
	void getExistingClaimEmptyQueryTest() {
		IdmLookup idmLookup = givenIdmLookupWithEmptyQuery();
		IdmQuery existingClaim = RelyingPartySetupUtil.getExistingIdmQuery(idmLookup, IDENTITY_QUERY, null);

		assertNull(existingClaim);
	}

	@Test
	void mergeAcWhiteListNullTest() {
		RelyingParty claimRule = givenRuleWithNullAcWhitelist();

		AcWhitelist baseClaimWhiteList = givenAcWhitelist();
		RelyingPartySetupUtil.mergeAcWhiteList(claimRule, baseClaimWhiteList);

		assertNotNull(claimRule.getAcWhitelist());
		assertEquals(claimRule.getAcWhitelist().getAcUrls().get(0), baseClaimWhiteList.getAcUrls().get(0));
		assertEquals(claimRule.getAcWhitelist().getAcUrls().size(), baseClaimWhiteList.getAcUrls().size());
	}

	@Test
	void mergeAcWhiteListEmptyTest() {
		RelyingParty claimRule = givenRuleWithEmptyAcWhitelist();
		AcWhitelist baseClaimWhiteList = givenAcWhitelist();
		RelyingPartySetupUtil.mergeAcWhiteList(claimRule, baseClaimWhiteList);

		assertNotNull(claimRule.getAcWhitelist());
		assertEquals(claimRule.getAcWhitelist().getAcUrls().get(0), baseClaimWhiteList.getAcUrls().get(0));
		assertEquals(claimRule.getAcWhitelist().getAcUrls().size(), baseClaimWhiteList.getAcUrls().size());
	}

	@Test
	void mergeAcWhiteListJoinTest() {
		RelyingParty claimRule = givenRuleWithAcWhiteList();
		int claimRespAttrSize = claimRule.getAcWhitelist().getAcUrls().size();
		AcWhitelist baseClaimWhiteList = givenAcWhitelist();
		RelyingPartySetupUtil.mergeAcWhiteList(claimRule, baseClaimWhiteList);

		assertNotNull(claimRule.getAcWhitelist());
		assertTrue(claimRule.getAcWhitelist().getAcUrls().size() > claimRespAttrSize);
	}

	private RelyingParty givenRuleWithAcWhiteList() {
		List<String> urls = new ArrayList<>();
		urls.add("http://URL1");

		AcWhitelist acWhitelist = new AcWhitelist();
		acWhitelist.setAcUrls(urls);

		RelyingParty claimRule = new RelyingParty();
		claimRule.setAcWhitelist(acWhitelist);

		return claimRule;
	}

	//IDM Response Attributes
	@Test
	void mergeIDMRespAttributesAttributesNullTest() {
		IdmQuery claimQuery = givenQueryWithCustPropAndRespAttNull();
		AttributesSelection baseIDMRespAttributes = giveBaseIdmAttributes();
		RelyingPartySetupUtil.mergeIdmRespAttributes(claimQuery, baseIDMRespAttributes);

		assertNotNull(claimQuery.getUserDetailsSelection());
		assertEquals(claimQuery.getUserDetailsSelection().getDefinitions().get(0),
				baseIDMRespAttributes.getDefinitions().get(0));
		assertEquals(claimQuery.getUserDetailsSelection().getDefinitions().size(),
				baseIDMRespAttributes.getDefinitions().size());
	}

	@Test
	void mergeIDMRespAttributesAttributesEmptyTest() {
		IdmQuery claimQuery = givenQueryWithCustPropAndRespAttrEmpty();
		AttributesSelection baseIDMRespAttributes = giveBaseIdmAttributes();
		RelyingPartySetupUtil.mergeIdmRespAttributes(claimQuery, baseIDMRespAttributes);

		assertNotNull(claimQuery.getUserDetailsSelection());
		assertEquals(claimQuery.getUserDetailsSelection().getDefinitions().get(0),
				baseIDMRespAttributes.getDefinitions().get(0));
		assertEquals(claimQuery.getUserDetailsSelection().getDefinitions().size(),
				baseIDMRespAttributes.getDefinitions().size());
	}

	@Test
	void mergeIDMRespAttributesJoinTest() {
		IdmQuery claimQuery = givenQueryWithUserDetails();
		int claimRespAttrSize = claimQuery.getUserDetailsSelection().getDefinitions().size();
		AttributesSelection baseIDMRespAttributes = giveBaseIdmAttributes();
		RelyingPartySetupUtil.mergeIdmRespAttributes(claimQuery, baseIDMRespAttributes);

		assertNotNull(claimQuery.getUserDetailsSelection());
		assertTrue(claimQuery.getUserDetailsSelection().getDefinitions().size() > claimRespAttrSize);
	}

	//Constant Attributes
	@Test
	void mergeConstantAttributesNullTest() {
		RelyingParty claimRule = givenRuleWithNullCpAndConstantAttributes();
		ConstAttributes baseConstantAttributes = givenBaseConstantAttributes();
		RelyingPartySetupUtil.mergeConstantAttributes(claimRule, baseConstantAttributes);

		List<Definition> attributeDefinitions = claimRule.getConstAttributes().getAttributeDefinitions();
		List<Definition> baseAttributeDefinitions = baseConstantAttributes.getAttributeDefinitions();
		assertNotNull(claimRule.getConstAttributes());
		assertEquals(attributeDefinitions.get(0).getName(), baseAttributeDefinitions.get(0).getName());
		assertEquals(attributeDefinitions.size(), baseAttributeDefinitions.size());
	}

	@Test
	void mergeConstantAttributesEmptyTest() {
		RelyingParty claimRule = givenRuleWithEmptyCpAndConstantAttributes();
		ConstAttributes baseConstantAttributes = givenBaseConstantAttributes();
		RelyingPartySetupUtil.mergeConstantAttributes(claimRule, baseConstantAttributes);

		assertNotNull(claimRule.getConstAttributes());
		List<Definition> attributeDefinitions = claimRule.getConstAttributes().getAttributeDefinitions();
		List<Definition> baseAttributeDefinitions = baseConstantAttributes.getAttributeDefinitions();
		assertEquals(attributeDefinitions.get(0).getName(), baseAttributeDefinitions.get(0).getName());
		assertEquals(attributeDefinitions.size(), baseAttributeDefinitions.size());
	}

	@Test
	void mergeConstantAttributesJoinTest() {
		RelyingParty claimRule = givenRuleWithCpAndConstantAttributes();
		int claimConstAttributeSize = claimRule.getConstAttributes().getAttributeDefinitions().size();
		ConstAttributes baseConstantAttributes = givenBaseConstantAttributes();
		RelyingPartySetupUtil.mergeConstantAttributes(claimRule, baseConstantAttributes);

		assertNotNull(claimRule.getConstAttributes());
		assertTrue(claimRule.getConstAttributes().getAttributeDefinitions().size() > claimConstAttributeSize);
	}

	@Test
	void mergeIdmQueriesNullBaseQueryTest() {
		var relyingParty = givenRelyingParty();
		var idmLookUp = givenIdmLookup();
		relyingParty.setIdmLookup(idmLookUp);
		var baseLookup = givenIdmLookupWithNullQuery();
		RelyingPartySetupUtil.mergeIdmQueries(relyingParty, baseLookup, List.of(idmQueryService));

		var original = givenIdmQueries();
		assertEquals(idmLookUp.getQueries(), original);
	}

	@Test
	void mergeIdmQueriesNullClaimQueryTest() {
		var relyingParty = givenRelyingParty();
		var idmLookUp = givenIdmLookupWithEmptyQuery();
		relyingParty.setIdmLookup(idmLookUp);

		var baseLookup = givenIdmLookup();
		var initialIdmQuerySize = idmLookUp.getQueries().size();
		RelyingPartySetupUtil.mergeIdmQueries(relyingParty, baseLookup, List.of(idmQueryService));

		assertNotEquals(initialIdmQuerySize, idmLookUp.getQueries().size());
		assertEquals(baseLookup.getQueries().size(), idmLookUp.getQueries().size());
	}

	@Test
	void mergeIdmQueriesSetIssuerClientIdFilterTest() {
		var relyingParty = givenRelyingParty();
		var idmLookUp = givenIdmLookupWithNoQueryParams();
		relyingParty.setIdmLookup(idmLookUp);
		var baseLookup = givenIdmLookup();
		RelyingPartySetupUtil.mergeIdmQueries(relyingParty, baseLookup, List.of(idmQueryService));

		assertNotSame("", idmLookUp.getQueries().get(1).getAppFilter());
		assertNotNull(idmLookUp.getQueries().get(1).getAppFilter());

		assertNotSame("", idmLookUp.getQueries().get(1).getClientExtId());
		assertNotNull(idmLookUp.getQueries().get(1).getClientExtId());

		assertNotSame("", idmLookUp.getQueries().get(1).getIssuerNameId());
		assertNotNull(idmLookUp.getQueries().get(1).getIssuerNameId());
	}

	//Certificates
	@Test
	void mergeCertificatesNoClaimCertTest() {
		RelyingParty claimRule = new RelyingParty();
		RelyingParty baseRule = givenRuleWithCertificates();
		RelyingPartySetupUtil.mergeCertificates(claimRule, baseRule);

		assertNotNull(claimRule.getCertificates());
		assertEquals(claimRule.getCertificates().getSignerKeystore(), baseRule.getCertificates().getSignerKeystore());
		assertEquals(claimRule.getCertificates().getSignerTruststore(), baseRule.getCertificates().getSignerTruststore());
	}

	@Test
	void mergeCertificatesNoClaimAndBaseCertTest() {
		RelyingParty claimRule = new RelyingParty();
		RelyingParty baseRule = new RelyingParty();
		RelyingPartySetupUtil.mergeCertificates(claimRule, baseRule);

		assertNull(claimRule.getCertificates());
	}

	@Test
	void mergeCertificatesMergeClaimSignerTest() {
		RelyingParty claimRule = givenRuleWithSignerKeystore();
		SignerKeystore claimInitialKeystore = claimRule.getCertificates().getSignerKeystore();
		RelyingParty baseRule = givenRuleWithTrustKeystore();
		RelyingPartySetupUtil.mergeCertificates(claimRule, baseRule);

		assertNotNull(claimRule.getCertificates());
		assertEquals(claimRule.getCertificates().getSignerKeystore(), claimInitialKeystore);
		assertEquals(claimRule.getCertificates().getSignerTruststore(), baseRule.getCertificates().getSignerTruststore());
	}

	@Test
	void mergeCertificatesMergeClaimTrustTest() {
		RelyingParty claimRule = givenRuleWithTrustKeystore();
		SignerTruststore claimInitialSignerTrust = claimRule.getCertificates().getSignerTruststore();
		RelyingParty baseRule = givenRuleWithSignerKeystore();
		RelyingPartySetupUtil.mergeCertificates(claimRule, baseRule);

		assertNotNull(claimRule.getCertificates());
		assertEquals(claimRule.getCertificates().getSignerTruststore(), claimInitialSignerTrust);
		assertEquals(claimRule.getCertificates().getSignerKeystore(), baseRule.getCertificates().getSignerKeystore());
	}

	@Test
	void mergeClaimsNullTest() {
		RelyingParty claimRule = null;
		RelyingParty baseClaimRule = new RelyingParty();
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();

		List<IdmQueryService> idmQueryServices = List.of(idmQueryService);
		TechnicalException exception = assertThrows(TechnicalException.class, () ->
				RelyingPartySetupUtil.mergeRelyingParty(claimRule, baseClaimRule, idmQueryServices, claimsProviderSetup)
		);

		assertEquals("RelyingParty is missing", exception.getInternalMessage());
	}

	@Test
	void mergeClaimsBaseNullTest() {
		RelyingParty claimRule = new RelyingParty();
		RelyingParty baseClaimRule = null;
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		RelyingPartySetupUtil.mergeRelyingParty(claimRule, baseClaimRule, List.of(idmQueryService), claimsProviderSetup);

		assertNotNull(claimRule);
	}

	@Test
	void mergeClaimsLookupNullTest() {
		RelyingParty claimRule = new RelyingParty();
		RelyingParty baseClaimRule = givenClaimWithLookup();
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		RelyingPartySetupUtil.mergeRelyingParty(claimRule, baseClaimRule, List.of(idmQueryService), claimsProviderSetup);

		assertNotNull(claimRule);
		assertNotNull(claimRule.getIdmLookup());
		assertEquals(claimRule.getIdmLookup(), baseClaimRule.getIdmLookup());
	}

	@Test
	void mergeClaimsIdmLookupMergeTest() {
		RelyingParty claimRule = givenClaimWithLookup();
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		RelyingParty baseClaimRule = givenBaseClaimWithLookup();
		RelyingPartySetupUtil.mergeRelyingParty(claimRule, baseClaimRule, List.of(idmQueryService), claimsProviderSetup);

		assertNotNull(claimRule);
		assertNotNull(claimRule.getIdmLookup());
		assertEquals(claimRule.getIdmLookup().getQueries().size(), baseClaimRule.getIdmLookup().getQueries().size());
	}

	//Load base claim
	@Test
	void loadBaseClaimNoBaseTest() {
		Collection<RelyingParty> claimRules = givenClaimRulesWithoutBase();
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		RelyingPartySetupUtil.loadRelyingParty(claimRules, RelyingPartySetupUtil.DEFINITION_PATH,
				CACHE_DEFINITION_PATH,null, List.of(idmQueryService), scriptService, claimsProviderSetup, null);

		assertNotNull(claimRules);
	}

	@Test
	void loadBaseClaimBaseDoesNotExistTest() {
		Collection<RelyingParty> claimRules = givenClaimRulesWithBase();
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		assertDoesNotThrow(() -> RelyingPartySetupUtil.loadRelyingParty(claimRules, RelyingPartySetupUtil.DEFINITION_PATH,
				CACHE_DEFINITION_PATH, null, List.of(idmQueryService), scriptService, claimsProviderSetup, null));
		assertDoesNotThrow(
				() -> RelyingPartySetupUtil.loadRelyingParty(claimRules, RelyingPartySetupUtil.DEFINITION_PATH,
						CACHE_DEFINITION_PATH, null, List.of(idmQueryService), scriptService, claimsProviderSetup, null));
		claimRules.forEach(rp -> assertEquals(FeatureEnum.INVALID, rp.getEnabled(), "RP " + rp.getId()));
	}

	@Test
	void loadRpInvalidXml() {
		var mappingFile = new File(RuleDefinitionUtilTest.class.getClassLoader().getResource(TEST_SETUP_RP_INVALID_XML).getFile());
		var result = XmlConfigUtil.loadConfigFromDirectory(mappingFile, RelyingParty.class);
		assertThat(result.skipped().size(), is(1));
		assertThat(result.skipped().keySet().iterator().next(), endsWith(TEST_SETUP_RP_INVALID_XML));
		assertThat(result.result(), hasSize(0));
	}

	@Test
	void loadBaseClaimMergeTest() {
		List<RelyingParty> claimRules = givenClaimRulesWithBase();
		String definitionPath = baseRuleFilePath();
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();

		RelyingPartySetupUtil.loadRelyingParty(claimRules, definitionPath, CACHE_PATH,
				null, List.of(idmQueryService), scriptService, claimsProviderSetup, null);

		assertNotNull(claimRules);
		assertNull(claimRules.get(0).getConstAttributes());
		assertNotNull(claimRules.get(0).getIdmLookup());
		assertEquals(FeatureEnum.TRUE, claimRules.get(0).getEnabled());
	}

	@Test
	void loadBaseClaimBaseInCache() {
		List<RelyingParty> claimRules = loadRulesWithCacheFromFile();
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		String newCacheDefinition = baseCacheRuleFilePath();

		RelyingPartySetupUtil.loadRelyingParty(claimRules, baseRuleFilePath(), newCacheDefinition, null,
				List.of(idmQueryService), scriptService, claimsProviderSetup, null);

		RelyingParty testRp = claimRules.get(0);

		assertEquals(TEST_CACHE_BASE_RULE, testRp.getBase());

		assertNotNull(testRp.getConstAttributes());
		assertNotNull(testRp.getConstAttributes().getAttributeDefinitions());
		assertNotNull(testRp.getCertificates());
		assertNotNull(testRp.getCertificates().getSignerTruststore());
		assertNotNull(testRp.getCertificates().getSignerKeystore());
		assertNotNull(testRp.getIdmLookup());
		assertNotNull(testRp.getIdmLookup().getQueries());
		assertEquals(2, testRp.getIdmLookup().getQueries().size());
		assertNotNull(testRp.getIdmLookup().getQueries().get(1).getUserDetailsSelection());
		assertNotNull(testRp.getIdmLookup().getQueries().get(1).getClientExtId());
	}

	@Test
	void loadSetupRpTest() {
		var relyingParties = loadRelyingParties();
		assertEquals(TestConstants.VALID_TEST_RPS, relyingParties.size());
		assertEquals(TestConstants.INVALID_TEST_RPS,
				relyingParties.stream().filter(rp -> rp.getEnabled() == FeatureEnum.INVALID).toList().size());
	}

	@Test
	void loadSetupCpTest() {
		var claimParties = loadClaimsParties();
		assertEquals(TestConstants.VALID_TEST_CPS, claimParties.size());
	}

	@Test
	void loadBaseClaimFromFileAndMergeWithBaseTest() {
		var relyingParties = loadRelyingParties();
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();

		var properties = new TrustBrokerProperties();
		properties.setGlobalProfilesPath("profiles");
		RelyingPartySetupUtil.loadRelyingParty(relyingParties, baseRuleFilePath(), "cache/", properties,
				List.of(idmQueryService), scriptService, claimsProviderSetup, null);
		assertEquals(TestConstants.VALID_TEST_RPS, relyingParties.size());

		validateTestRp(relyingParties, "urn:test:SAMPLERP");

		validateTestRp(relyingParties, "urn:test:TESTRP");

		validateRpInSubDir(relyingParties, "urn:test:TEST_APPLICATION_LOCAL_PROFILE", "certs/test-application-cert.pem");

		validateRpInSubDir(relyingParties, "urn:test:TEST_APPLICATION_STANDARD_PROFILE", "test-cert.pem");

		validateRpInSubDir(relyingParties, "urn:test:TEST_APPLICATION_GLOBAL_PROFILE","global/global-cert.pem");

		validateRpInSubDir(relyingParties, "urn:test:TEST_APPLICATION_GROUP_PROFILE","application_group/group-cert.pem");

		assertTrue(relyingParties.stream().anyMatch(rp -> rp.getId().equals("urn:test:GROUP1")));
		assertTrue(relyingParties.stream().anyMatch(rp -> rp.getId().equals("urn:test:GROUP2")));
	}

	private static void validateTestRp(List<RelyingParty> relyingParties, String anObject) {
		var testRp = findRpById(relyingParties, anObject);
		assertEquals(true, testRp.isValid());
		assertEquals("", testRp.getSubPath());
		assertNotNull(testRp.getConstAttributes());
		assertNotNull(testRp.getConstAttributes()
							.getAttributeDefinitions());
		assertNotNull(testRp.getCertificates());
		assertNotNull(testRp.getCertificates()
							.getSignerKeystore());
		assertNotNull(testRp.getIdmLookup());
		assertNotNull(testRp.getIdmLookup()
							.getQueries());
		assertEquals(2, testRp.getIdmLookup()
							  .getQueries()
							  .size());
		assertNotNull(testRp.getIdmLookup()
							.getQueries()
							.get(1)
							.getUserDetailsSelection());
		assertNotNull(testRp.getIdmLookup()
							.getQueries()
							.get(1)
							.getClientExtId());
	}

	private static void validateRpInSubDir(List<RelyingParty> relyingParties, String anObject, String expected) {
		var testApplicationStandardProfileRp = findRpById(relyingParties, anObject);
		assertEquals(true, testApplicationStandardProfileRp.isValid());
		assertEquals("test_application", testApplicationStandardProfileRp.getSubPath());
		assertEquals(expected, testApplicationStandardProfileRp.getCertificates()
															   .getSignerKeystore()
															   .getCertPath());
	}

	@Test
	void mergeScriptsTest() {
		RelyingParty relyingParty = givenRelyingPartyWithScripts();
		Scripts baseScripts = givenBaseScripts();

		relyingParty.setScripts(null);
		RelyingPartySetupUtil.mergeScripts(relyingParty, baseScripts);
		assertNotNull(relyingParty.getScripts());
		assertEquals(relyingParty.getScripts().getScripts().size(), baseScripts.getScripts().size());
		assertEquals(relyingParty.getScripts().getScripts().get(0).getName(), baseScripts.getScripts().get(0).getName());

		RelyingParty relyingParty2 = givenRelyingPartyWithScripts();
		RelyingPartySetupUtil.mergeScripts(relyingParty2, null);
		assertNotNull(relyingParty.getScripts());

	}

	@Test
	void joinAndDistinctScriptsTest() {
		Scripts baseScripts = givenBaseScripts();
		String baseOldName = baseScripts.getScripts().get(0).getName();
		String baseOldType = baseScripts.getScripts().get(0).getType();
		Scripts rpScripts = givenRpScripts();
		RelyingPartySetupUtil.joinAndDistinctScripts(rpScripts, baseScripts);
		assertEquals(3, baseScripts.getScripts().size());
		assertEquals(baseScripts.getScripts().get(0).getName(), baseOldName);
		assertEquals(baseScripts.getScripts().get(0).getType(), baseOldType);

		baseScripts.getScripts().get(0).setName(null);
		assertThrows(TechnicalException.class, () -> RelyingPartySetupUtil.joinAndDistinctScripts(rpScripts, baseScripts));
	}

	@ParameterizedTest
	@CsvSource(value = {
			"https://example.trustbroker.swiss,TRUE",
			"https://invalid.example.trustbroker.swiss/path#fragment,INVALID"
	})
	void loadValidOidcClient(String cUrl, FeatureEnum expectedEnabled) {
		var rp = givenRelyingParty();
		rp.setOidc(givenOidcClient(List.of(cUrl)));
		var claimRules = List.of(rp);
		var definitionPath = baseRuleFilePath();
		var claimsProviderSetup = ClaimsProviderSetup.builder().build();
		assertDoesNotThrow(() -> RelyingPartySetupUtil.loadRelyingParty(claimRules, definitionPath, CACHE_PATH,
				null, List.of(idmQueryService), scriptService, claimsProviderSetup, null));
		assertThat(rp.getEnabled(), is(expectedEnabled));
	}

	private Oidc givenOidcClient(List<String> acUrls) {
		var redirectUris = AcWhitelist.builder().acUrls(acUrls).build();
		var clients = List.of(OidcClient.builder().id("clientId").redirectUris(redirectUris).build());
		return Oidc.builder().clients(clients).build();
	}

	private RelyingParty givenRelyingPartyWithScripts() {
		RelyingParty relyingParty = new RelyingParty();
		relyingParty.setScripts(givenRpScripts());

		return relyingParty;
	}


	private Scripts givenBaseScripts() {
		Scripts scripts = new Scripts();
		List<Script> rpScripts = new ArrayList<>();

		Script script1 = new Script();
		script1.setName("Test1.groovy");
		script1.setType("AfterIdm");
		Script script2 = new Script();
		script2.setName("Test3.groovy");
		script2.setType("AfterIdm");

		rpScripts.add(script1);
		rpScripts.add(script2);

		scripts.setScripts(rpScripts);

		return scripts;

	}

	private Scripts givenRpScripts() {
		Scripts scripts = new Scripts();
		List<Script> rpScripts = new ArrayList<>();

		Script script1 = new Script();
		script1.setName("Test1.groovy");
		script1.setType("AfterIdm");
		Script script2 = new Script();
		script2.setName("Test2.groovy");
		script2.setType("AfterIdm");

		rpScripts.add(script1);
		rpScripts.add(script2);

		scripts.setScripts(rpScripts);

		return scripts;
	}

	private RelyingParty givenRuleWithEmptyAcWhitelist() {
		AcWhitelist acWhitelist = new AcWhitelist();
		acWhitelist.setAcUrls(Collections.emptyList());

		RelyingParty claimRule = new RelyingParty();
		claimRule.setAcWhitelist(acWhitelist);
		return claimRule;
	}

	private AcWhitelist givenAcWhitelist() {
		List<String> acUrls = new ArrayList<>();
		acUrls.add("http://testURl1");
		acUrls.add("http://testUrl2");

		AcWhitelist acWhitelist = new AcWhitelist();
		acWhitelist.setAcUrls(acUrls);

		return acWhitelist;
	}

	private RelyingParty givenRuleWithNullAcWhitelist() {
		RelyingParty claimRule = new RelyingParty();
		claimRule.setAcWhitelist(null);
		return claimRule;

	}

	private List<RelyingParty> loadRelyingParties() {
		var definition = RuleDefinitionUtilTest.class.getClassLoader().getResource(TEST_SETUP_RP).getFile();
		var relyingPartySetup = ClaimsProviderUtil.loadRelyingPartySetup(definition);
		return relyingPartySetup.getRelyingParties();
	}

	private List<ClaimsParty> loadClaimsParties() {
		var definition = RuleDefinitionUtilTest.class.getClassLoader().getResource(TEST_SETUP_CP).getFile();
		var claimsProviderSetup = ClaimsProviderUtil.loadClaimsProviderSetup(definition);
		return claimsProviderSetup.getClaimsParties();
	}

	private List<RelyingParty> loadRulesWithCacheFromFile() {
		String ruleDefinition =
				RuleDefinitionUtilTest.class.getClassLoader().getResource(TEST_RULE_WITH_CACHE_BASE_DEFINITIONS).getFile();
		RelyingPartySetup rulesDefinitions = ClaimsProviderUtil.loadRelyingPartySetup(ruleDefinition);
		return rulesDefinitions.getRelyingParties();
	}

	private List<RelyingParty> givenClaimRulesWithBase() {
		RelyingParty claimRule = givenRelyingParty();
		return Collections.singletonList(claimRule);
	}

	private static RelyingParty givenRelyingParty() {
		return RelyingParty.builder()
						   .id("urn:urn")
						   .base(TEST_BASE_PROFILE)
						   .build();
	}

	private static String baseRuleFilePath() {
		return getBaseProfilePath().replace(TEST_BASE_PROFILE, "");
	}

	private static String baseCacheRuleFilePath() {
		return getBaseProfilePath().replace(TEST_BASE_STANDARD, CACHE_PATH);
	}

	private static String getBaseProfilePath() {
		return RuleDefinitionUtilTest.class.getClassLoader()
										   .getResource(TEST_BASE_STANDARD)
										   .getFile();
	}

	private Collection<RelyingParty> givenClaimRulesWithoutBase() {
		List<RelyingParty> claimRules = new ArrayList<>();

		RelyingParty claimRule = new RelyingParty();

		claimRules.add(claimRule);

		return claimRules;
	}

	private RelyingParty givenClaimWithLookup() {
		RelyingParty claimRule = new RelyingParty();
		claimRule.setIdmLookup(givenIdmLookupWithEmptyQuery());
		return claimRule;
	}

	private RelyingParty givenBaseClaimWithLookup() {
		RelyingParty claimRule = new RelyingParty();
		claimRule.setIdmLookup(givenIdmLookup());
		return claimRule;
	}

	private IdmLookup givenIdmLookupWithNoQueryParams() {
		IdmLookup idmLookup = new IdmLookup();
		IdmQuery globalQuery = IdmQuery.builder().name(GLOBAL_QUERY).build();
		globalQuery.setSubjectNameId("subjectNameid");
		List<IdmQuery> idmQueries = new ArrayList<>();
		idmQueries.add(globalQuery);
		idmLookup.setQueries(idmQueries);
		return idmLookup;
	}

	private RelyingParty givenRuleWithCertificates() {
		Certificates certificates = new Certificates();
		certificates.setSignerTruststore(givenSignerTruststore());
		certificates.setSignerKeystore(givenSignerKeystore());

		RelyingParty claimRule = new RelyingParty();
		claimRule.setCertificates(certificates);
		return claimRule;

	}

	private RelyingParty givenRuleWithSignerKeystore() {
		Certificates certificates = new Certificates();
		certificates.setSignerKeystore(givenSignerKeystore());

		RelyingParty claimRule = new RelyingParty();
		claimRule.setCertificates(certificates);
		return claimRule;

	}

	private RelyingParty givenRuleWithTrustKeystore() {
		Certificates certificates = new Certificates();
		certificates.setSignerTruststore(givenSignerTruststore());

		RelyingParty claimRule = new RelyingParty();
		claimRule.setCertificates(certificates);
		return claimRule;

	}

	private SignerKeystore givenSignerKeystore() {
		return new SignerKeystore("cet.key", "alias", "", "pass", "keyPath.key");

	}

	private SignerTruststore givenSignerTruststore() {
		return new SignerTruststore("cet.key", "alias", "", "pass", "keyPath.key");
	}

	private RelyingParty givenRuleWithCpAndConstantAttributes() {
		AttributesSelection userDetailsSelection = new AttributesSelection();
		userDetailsSelection.setDefinitions(givenAttributeLists());

		ConstAttributes constAttributes = new ConstAttributes();
		constAttributes.setAttributeDefinitions(givenConstantAttributes());

		RelyingParty claimRule = new RelyingParty();
		claimRule.setConstAttributes(constAttributes);
		return claimRule;

	}

	private ConstAttributes givenBaseConstantAttributes() {
		ConstAttributes constAttributes = new ConstAttributes();
		constAttributes.setAttributeDefinitions(givenBaseConstantAttributesDefinitions());

		return constAttributes;
	}

	private List<Definition> givenBaseConstantAttributesDefinitions() {
		List<Definition> attributeDefinitions = new ArrayList<>();
		Definition attributeDefinition = new Definition("TestBaseConstantAttribute", "TestBaseNamespace", "222");

		attributeDefinitions.add(attributeDefinition);
		return attributeDefinitions;
	}

	private List<Definition> givenConstantAttributes() {
		List<Definition> attributeDefinitions = new ArrayList<>();
		Definition attributeDefinition = new Definition("TestConstantAttribute", "TestNamespace", "500");

		attributeDefinitions.add(attributeDefinition);
		return attributeDefinitions;
	}

	private RelyingParty givenRuleWithEmptyCpAndConstantAttributes() {
		AttributesSelection userDetailsSelection = new AttributesSelection();
		userDetailsSelection.setDefinitions(Collections.emptyList());

		ConstAttributes constAttributes = new ConstAttributes();
		constAttributes.setAttributeDefinitions(Collections.emptyList());

		RelyingParty claimRule = new RelyingParty();
		claimRule.setConstAttributes(constAttributes);
		return claimRule;
	}

	private RelyingParty givenRuleWithNullCpAndConstantAttributes() {
		RelyingParty claimRule = new RelyingParty();
		claimRule.setConstAttributes(null);
		return claimRule;
	}

	private IdmQuery givenQueryWithUserDetails() {
		AttributesSelection idmUserDetailsSelection = new AttributesSelection();
		idmUserDetailsSelection.setDefinitions(givenBaseAttributeList());
		return IdmQuery.builder()
					   .name(GLOBAL_QUERY)
					   .userDetailsSelection(idmUserDetailsSelection)
					   .clientExtId("2323")
					   .issuerNameId("3434")
					   .appFilter("filter")
					   .build();
	}

	private IdmQuery givenQueryWithCustPropAndRespAttrEmpty() {
		AttributesSelection idmUserDetailsSelection = new AttributesSelection();
		idmUserDetailsSelection.setDefinitions(Collections.emptyList());
		return IdmQuery.builder()
					   .name(GLOBAL_QUERY)
					   .userDetailsSelection(idmUserDetailsSelection)
					   .clientExtId("2323")
					   .issuerNameId("3434")
					   .appFilter("filter")
					   .build();
	}

	private IdmQuery givenQueryWithCustPropAndRespAttNull() {
		return IdmQuery.builder()
					   .name(GLOBAL_QUERY)
					   .clientExtId("2323")
					   .issuerNameId("3434")
					   .appFilter("filter")
					   .build();
	}

	private AttributesSelection giveBaseIdmAttributes() {
		return givenResponseAttributes();
	}

	private IdmLookup givenIdmLookupWithEmptyQuery() {
		List<IdmQuery> idmQueries = new ArrayList<>();

		IdmLookup idmLookup = new IdmLookup();
		idmLookup.setQueries(idmQueries);

		return idmLookup;

	}

	private IdmLookup givenIdmLookupWithNullQuery() {
		IdmLookup idmLookup = new IdmLookup();
		idmLookup.setQueries(null);

		return idmLookup;
	}

	private IdmLookup givenIdmLookup() {
		IdmLookup idmLookup = new IdmLookup();
		idmLookup.setQueries(givenIdmQueries());

		return idmLookup;
	}

	private List<IdmQuery> givenIdmQueries() {
		List<IdmQuery> idmQueries = new ArrayList<>();

		IdmQuery globalQuery = IdmQuery.builder()
									   .name(GLOBAL_QUERY)
									   .userDetailsSelection(givenResponseAttributes())
									   .clientExtId("2323")
									   .issuerNameId("3434")
									   .appFilter("filter")
									   .build();
		idmQueries.add(globalQuery);

		IdmQuery identityQuery = IdmQuery.builder()
										 .name(IDENTITY_QUERY)
										 .userDetailsSelection(givenResponseAttributes())
										 .clientExtId("2323")
										 .issuerNameId("3434")
										 .appFilter("filter")
										 .build();
		idmQueries.add(identityQuery);

		return idmQueries;
	}

	private AttributesSelection givenResponseAttributes() {
		AttributesSelection idmUserDetailsSelection = new AttributesSelection();
		idmUserDetailsSelection.setDefinitions(givenAttributeLists());

		return idmUserDetailsSelection;

	}

	private static List<Definition> givenAttributeLists() {
		List<Definition> attributes = new ArrayList<>();
		Definition definition = new Definition("UnitName", "http://schema.namespace", "");
		attributes.add(definition);

		return attributes;
	}

	private static List<String> givenAcWhiteListDuplicatesWithBaseLists() {
		List<String> attributes = new ArrayList<>();
		attributes.add("http://test.sp1.trustbroker.swiss");
		attributes.add("http://test.sp2.trustbroker.swiss");

		return attributes;
	}

	private static List<String> givenBaseAcWhiteListList() {
		List<String> attributes = new ArrayList<>();
		attributes.add("http://test.sp1.trustbroker.swiss");
		attributes.add("http://test.sp3.trustbroker.swiss");

		return attributes;
	}

	private static List<Definition> givenAttributeDuplicatesWithBaseLists() {
		List<Definition> attributes = new ArrayList<>();
		Definition definition1 = new Definition("FirstName", "http://schema.namespace");
		Definition definition2 = new Definition("UnitName", "http://schema.namespace");
		attributes.add(definition1);
		attributes.add(definition2);

		return attributes;
	}

	private static List<Definition> givenBaseAttributeList() {
		List<Definition> baseAttributes = new ArrayList<>();
		Definition definition1 = new Definition("FirstName", "http://schema.namespace");
		Definition definition2 = new Definition("LastName", "http://schema.namespace");
		baseAttributes.add(definition1);
		baseAttributes.add(definition2);

		return baseAttributes;
	}

	private static RelyingParty findRpById(List<RelyingParty> relyingParties, String anObject) {
		return relyingParties.stream()
				.filter(rp -> rp.getId().equals(anObject))
				.findFirst()
				.orElseThrow();
	}
}
