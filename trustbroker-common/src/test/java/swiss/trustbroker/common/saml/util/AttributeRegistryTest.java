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

package swiss.trustbroker.common.saml.util;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.test.saml.util.SamlTestBase;

class AttributeRegistryTest {

	@BeforeEach
	void setup() {
		new CoreAttributeInitializer().init();
	}

	@AfterEach
	void teardown() {
		// undo side effects
		AttributeRegistry.clear();
		CoreAttributeName.SSO_SESSION_ID.setNamespaceUri(null);
		CoreAttributeName.SSO_SESSION_ID.setAltName(null);
		CoreAttributeName.SSO_SESSION_ID.setOidcNameList(null);
	}

	@Test
	void testOverridePutAttributeName() {
		var originalCopy = SamlTestBase.TestAttributeName.of(CoreAttributeName.CLAIMS_NAME);
		var overwrite = givenAttribute(originalCopy.getName());
		AttributeRegistry.putAttributeName(overwrite);
		// unchanged, overwrite registered under modified names:
		assertSame(originalCopy, CoreAttributeName.CLAIMS_NAME);
		assertThat(AttributeRegistry.forName(originalCopy.getName()), is(CoreAttributeName.CLAIMS_NAME));
		assertThat(AttributeRegistry.forName(originalCopy.getNamespaceUri()), is(CoreAttributeName.CLAIMS_NAME));
		assertThat(AttributeRegistry.forName(overwrite.getNamespaceUri()), is(overwrite));
		assertThat(AttributeRegistry.forName(overwrite.getAltName()), is(overwrite));
		assertThat(AttributeRegistry.forName(overwrite.getOidcNameList().get(0)), is(overwrite));
		assertThat(AttributeRegistry.forName(overwrite.getOidcNameList().get(1)), is(overwrite));
	}

	@Test
	void testOverrideUpdateAttributeNameFromConfig() {
		var overwrite = givenAttribute(CoreAttributeName.SSO_SESSION_ID.getName());
		AttributeRegistry.updateAttributeNameFromConfig(overwrite);
		// changed original values, original registered under modified names:
		assertSame(overwrite, CoreAttributeName.SSO_SESSION_ID);
		verifyRegistered(overwrite, CoreAttributeName.SSO_SESSION_ID);
	}

	@Test
	void testOverridePutAttributeNameByCore() {
		var overwrite = givenAttribute("custom");
		AttributeRegistry.putAttributeName(overwrite);
		// overwrite registered under modified names:
		assertThat(AttributeRegistry.forName(overwrite.getName()), is(overwrite));
		assertThat(AttributeRegistry.forName(overwrite.getNamespaceUri()), is(overwrite));

		var overwriteConfig = givenAttribute(CoreAttributeName.SSO_SESSION_ID.getName());
		AttributeRegistry.updateAttributeNameFromConfig(overwriteConfig);
		// changed original values, core registered under modified names:
		assertSame(overwriteConfig, CoreAttributeName.SSO_SESSION_ID);
		assertThat(AttributeRegistry.forName(overwrite.getName()), is(overwrite));
		verifyRegistered(overwriteConfig, CoreAttributeName.SSO_SESSION_ID);
	}

	private static void verifyRegistered(AttributeName names, AttributeName expected) {
		assertThat(AttributeRegistry.forName(names.getName()), is(expected));
		assertThat(AttributeRegistry.forName(names.getNamespaceUri()), is(expected));
		assertThat(AttributeRegistry.forName(names.getAltName()), is(expected));
		assertThat(AttributeRegistry.forName(names.getOidcNameList().get(0)), is(expected));
		assertThat(AttributeRegistry.forName(names.getOidcNameList().get(1)), is(expected));
	}

	private static SamlTestBase.TestAttributeName givenAttribute(String name) {
		return SamlTestBase.TestAttributeName.builder()
				.name(name)
				.namespaceUri("ns1")
				.altName("alt1")
				.oidcNameList(List.of("oidc1", "oidc2"))
				.build();
	}

	private static void assertSame(AttributeName expected, AttributeName actual) {
		assertThat(actual.getName(), is(expected.getName()));
		assertThat(actual.getNamespaceUri(), is(expected.getNamespaceUri()));
		assertThat(actual.getAltName(), is(expected.getAltName()));
		assertThat(actual.getOidcNameList(), is(expected.getOidcNameList()));
	}

}
