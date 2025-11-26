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

package swiss.trustbroker.script.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doReturn;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TestConstants;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.Script;
import swiss.trustbroker.federation.xmlconfig.Scripts;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.homerealmdiscovery.util.RelyingPartySetupUtil;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = ScriptService.class)
class ScriptServiceTest {

	private static final String SCRIPTS_PATH = "scripts/"; // on classpath

	private static final String GLOBAL_SCRIPTS_PATH = "global/";

	private static final String TENANT1_PATH = "tenant1/";

	private static final String TENANT2_PATH = "tenant2/app1/";

	private static final String REMOVE_IDM_USER_DETAILS_AFTER_IDM = "RemoveIdmUserDetailsAfterIdm.groovy";

	private static final String ADJUST_OIDC_ATTRIBUTE_NAMES = "AdjustOidcAttributeNames.groovy";

	private static final String ENCODE_PASSWORD = "EncodePassword.groovy";

	@Autowired
	ScriptService scriptService;

	@MockitoBean
	RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	TrustBrokerProperties trustBrokerProperties;

	@BeforeEach
	void setup() {
		SamlInitializer.initSamlSubSystem();
	}

	@Test
	void testRemoveIdmUserDetailsAfterIdm() {
		String scriptName = SCRIPTS_PATH + TENANT1_PATH + REMOVE_IDM_USER_DETAILS_AFTER_IDM;
		// beans
		CpResponse cpResponse = givenResponseWithIdmUserDetails();
		int originSize1 = cpResponse.getAttributes().size();
		int userSize1 = cpResponse.getUserDetails().size();
		// process
		scriptService.init(scriptName);
		scriptService.processOnResponse(scriptName, cpResponse, null, null, null);
		// process (removes one query)
		int originSize2 = cpResponse.getAttributes().size();
		int userSize2 = cpResponse.getUserDetails().size();
		assertEquals(userSize1 + 1, userSize2,
				"Groovy script " + scriptName + " did not manipulate USERDETAILS as expected");
		assertEquals(originSize1 + 1, originSize2,
				"Groovy script " + scriptName + " did not manipulate ORIGINATTRS as expected");
	}

	@Test
	void testShortSamlAttributeNames() {
		String scriptName = SCRIPTS_PATH + TENANT2_PATH + ADJUST_OIDC_ATTRIBUTE_NAMES;

		// data
		var cpResponse = CpResponse.builder()
								   .attributes(Map.of(
										   Definition.builder()
													 .namespaceUri("http://fq.stuff.1/name1")
													 .build(), List.of("value1")
								   ))
								   .userDetails(Map.of(
										   Definition.builder()
													 .namespaceUri("http://fq.stuff.2/name2")
													 .build(), List.of("value2")
								   ))
								   .properties(Map.of(
										   Definition.builder()
													 .namespaceUri("http://fq.stuff.3/name3")
													 .build(), List.of("value3")
								   ))
								   .rpContext(Map.of(
										   HttpHeaders.REFERER, "https://identity-test.trustbroker.swiss"
								   ))
								   .build();
		// process
		scriptService.init(scriptName);
		scriptService.processOnResponse(scriptName, cpResponse, null, null, null);

		// check (arbitrary which entry of the above wins)
		assertEquals("value1", cpResponse.getAttribute("name1"));
		assertEquals("value2", cpResponse.getUserDetail("name2"));
		assertEquals("value3", cpResponse.getProperty("name3"));
	}

	@Test
	void testCompileScripts() {
		var scriptsPath = SamlTestBase.filePathFromClassPath(SCRIPTS_PATH);
		var globalScriptsPath = scriptsPath + GLOBAL_SCRIPTS_PATH;
		var result = scriptService.compileScripts(scriptsPath, globalScriptsPath);
		assertThat(result.keySet(), containsInAnyOrder(
				ENCODE_PASSWORD,
				TENANT1_PATH + REMOVE_IDM_USER_DETAILS_AFTER_IDM,
				TENANT2_PATH + ADJUST_OIDC_ATTRIBUTE_NAMES));
	}

	@Test
	void testResolveScripts() {
		// load scripts
		var configPath = SamlTestBase.filePathFromClassPath(TestConstants.LATEST_PATH).replace(TestConstants.LATEST_PATH, "");
		doReturn(configPath).when(trustBrokerProperties).getConfigurationPath();
		doReturn(RelyingPartySetupUtil.DEFINITION_PATH).when(trustBrokerProperties).getScriptPath();
		doReturn(SCRIPTS_PATH).when(trustBrokerProperties).getGlobalScriptPath();
		scriptService.prepareRefresh();
		scriptService.activateRefresh();

		// resolve
		var type = "OnCpRequest";
		var subPath = "test_application";
		var relativeToSubPath = Script.builder().name("groovy/TestApplication.groovy").type(type).build();
		var relativeToTop = Script.builder().name("application_group/ApplicationGroup.groovy").type(type).build();
		var relativeToGlobalScripts = Script.builder().name("GlobalRequest.groovy").type(type).build();
		var wrongType = Script.builder().name("GlobalResponse.groovy").type("BeforeIdm").build();
		var scripts = Scripts.builder().scripts(List.of(relativeToSubPath, wrongType, relativeToTop, relativeToGlobalScripts)).build();
		var result = scriptService.resolveScripts(scripts, subPath, type);
		var resultScriptNames = result.stream().map(Pair::getKey).toList();
		assertThat(resultScriptNames, containsInAnyOrder(
				Path.of(subPath, relativeToSubPath.getName()).toString(), // result has the full path
				relativeToTop.getName(),
				relativeToGlobalScripts.getName()));
	}

	private static CpResponse givenResponseWithIdmUserDetails() {
		CpResponse cpResponse = new CpResponse();
		// CP data
		Map<Definition, List<String>> cpAttrs = new HashMap<>();
		cpAttrs.put(Definition.builder().name("ORIGIN1").build(), List.of("ORIGIN-VALUE1"));
		cpResponse.setAttributes(cpAttrs);
		// IDM data
		Map<Definition, List<String>> userDetails = new HashMap<>();
		userDetails.put(Definition.builder().name("SHORT1").namespaceUri("LONG1").build(), List.of("VALUE1"));
		cpResponse.setUserDetails(userDetails);
		return cpResponse;
	}

}
