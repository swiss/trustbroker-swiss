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

package swiss.trustbroker.saml.dto;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;

class RpRequestTest {

	private static final String CONTEXT_CLASS_1 = "weak";

	private static final String CONTEXT_CLASS_2 = "normal";

	private static final String CONTEXT_CLASS_3 = "strong";

	private static final String CP_1 = "cp1";

	private static final String CP_2 = "cp2";

	private static final String CP_3 = "cp3";

	@Test
	void testClaimsProviders() {
		var rpRequest = givenRpRequest();

		assertFalse(rpRequest.hasSingleClaimsProvider());

		var cp = rpRequest.getClaimsProvider(CP_1);
		assertThat(cp, is(not(nullValue())));
		assertThat(cp.getId(), is(CP_1));
		cp = rpRequest.dropClaimsProvider(CP_1);
		assertThat(cp, is(not(nullValue())));
		assertThat(cp.getId(), is(CP_1));
		cp = rpRequest.retainClaimsProvider(CP_1);
		// retain if not present has no effect:
		assertThat(cp, is(nullValue()));
		assertFalse(rpRequest.hasSingleClaimsProvider());

		cp = rpRequest.retainClaimsProvider(CP_3);
		assertThat(cp, is(not(nullValue())));
		assertThat(cp.getId(), is(CP_3));
		assertTrue(rpRequest.hasSingleClaimsProvider());
		cp = rpRequest.getClaimsProvider(CP_3);
		assertThat(cp, is(not(nullValue())));
		assertThat(cp.getId(), is(CP_3));
	}

	@Test
	void testContextClass() {
		var rpRequest = givenRpRequest();
		// existing
		assertFalse(rpRequest.addContextClass(CONTEXT_CLASS_1));

		// new
		assertFalse(rpRequest.hasContextClass(CONTEXT_CLASS_3));
		assertTrue(rpRequest.addContextClass(CONTEXT_CLASS_3));
		assertTrue(rpRequest.hasContextClass(CONTEXT_CLASS_3));
		assertTrue(rpRequest.removeContextClass(CONTEXT_CLASS_3));
		assertFalse(rpRequest.hasContextClass(CONTEXT_CLASS_3));

		// retain
		assertTrue(rpRequest.retainContextClass(CONTEXT_CLASS_2));
		assertThat(rpRequest.getContextClasses(), is(List.of(CONTEXT_CLASS_2)));
		assertFalse(rpRequest.retainContextClass(CONTEXT_CLASS_2));
		// retain if not present has no effect:
		assertFalse(rpRequest.retainContextClass(CONTEXT_CLASS_1));
		assertThat(rpRequest.getContextClasses(), is(List.of(CONTEXT_CLASS_2)));
	}

	private static RpRequest givenRpRequest() {
		var rpRequest = new RpRequest();
		List<String> contextClasses = new ArrayList<>(List.of(CONTEXT_CLASS_1, CONTEXT_CLASS_2));
		rpRequest.setContextClasses(contextClasses);
		List<ClaimsProvider> cps = new ArrayList<>(List.of(
				ClaimsProvider.builder().id(CP_1).build(),
				ClaimsProvider.builder().id(CP_2).build(),
				ClaimsProvider.builder().id(CP_3).build()));
		rpRequest.setClaimsProviders(cps);
		return rpRequest;
	}

}
