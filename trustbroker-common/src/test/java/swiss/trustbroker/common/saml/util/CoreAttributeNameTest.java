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
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.HashSet;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class CoreAttributeNameTest {

	private static final Logger log = LoggerFactory.getLogger(CoreAttributeNameTest.class);

	private static final int ALL_NAMES_COUNT = CoreAttributeName.values().length;

	private static final int NO_FQ_NAME = 6;

	private static final int ALL_FQ_NAMES_COUNT = ALL_NAMES_COUNT - NO_FQ_NAME;

	@BeforeAll
	static void setup() {
		new CoreAttributeInitializer().init();
	}

	@Test
		// for auditing we need to make sure, FQ.names are collision free
	void testUniqueness() {
		// FQ names total
		var arrCnt = Arrays.stream(CoreAttributeName.values()).filter(
				attribute -> attribute.getNamespaceUri() != null).count();
		// FQ names duplicates
		var set = new HashSet<String>();
		for (var attribute : CoreAttributeName.values()) {
			assertThat(AttributeRegistry.forName(attribute.getName()), is(attribute));
			if (attribute.getNamespaceUri() != null) {
				assertThat(AttributeRegistry.forName(attribute.getNamespaceUri()), is(attribute));
				if (!set.add(attribute.getNamespaceUri())) {
					log.warn("Duplicate FQ found: {} => {}", attribute, attribute.getNamespaceUri());
				}
			}
			if (attribute.getAltName() != null) {
				assertThat(AttributeRegistry.forName(attribute.getAltName()), is(attribute));
			}
			if (attribute.getOidcNameList() != null) {
				for (var oidcName : attribute.getOidcNameList()) {
					assertThat(AttributeRegistry.forName(oidcName), is(attribute));
				}
			}
		}
		assertEquals(ALL_FQ_NAMES_COUNT, arrCnt);
		assertEquals(ALL_FQ_NAMES_COUNT, set.size());
	}

	@Test
	void testForName() {
		assertThat(AttributeRegistry.forName(CoreAttributeName.NAME.getNamespaceUri()),
				is(CoreAttributeName.NAME));
		assertThat(AttributeRegistry.forName(CoreAttributeName.CLAIMS_NAME.getName()),
				is(CoreAttributeName.CLAIMS_NAME));
		assertThat(AttributeRegistry.forName(CoreAttributeName.EMAIL.getOidcNameList().get(0)),
				is(CoreAttributeName.EMAIL));
	}

}
