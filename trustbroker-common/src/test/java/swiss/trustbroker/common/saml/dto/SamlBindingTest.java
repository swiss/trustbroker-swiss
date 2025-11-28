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

package swiss.trustbroker.common.saml.dto;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.saml.common.xml.SAMLConstants;
import swiss.trustbroker.common.exception.RequestDeniedException;

class SamlBindingTest {

	@ParameterizedTest
	@MethodSource
	void compatibleWithRequestedBinding(SamlBinding responseBinding, SamlBinding requestedBinding, boolean expected) {
		assertThat(responseBinding.compatibleWithRequestedBinding(requestedBinding), is(expected));
	}

	static Object[][] compatibleWithRequestedBinding() {
		return new Object[][] {
				{ SamlBinding.ARTIFACT, null, true },
				{ SamlBinding.ARTIFACT, SamlBinding.ARTIFACT, true },
				{ SamlBinding.ARTIFACT, SamlBinding.POST, true }, // ARTIFACT response to POST OK
				{ SamlBinding.ARTIFACT, SamlBinding.REDIRECT, true }, // ARTIFACT response to REDIRECT OK
				{ SamlBinding.ARTIFACT, SamlBinding.SOAP, false },
				{ SamlBinding.POST, null, true },
				{ SamlBinding.POST, SamlBinding.POST, true },
				{ SamlBinding.POST, SamlBinding.REDIRECT, true }, // special case
				{ SamlBinding.POST, SamlBinding.ARTIFACT, false },
				{ SamlBinding.POST, SamlBinding.SOAP, false },
				{ SamlBinding.REDIRECT, null, true },
				{ SamlBinding.REDIRECT, SamlBinding.REDIRECT, true },
				{ SamlBinding.REDIRECT, SamlBinding.POST, false },
				{ SamlBinding.REDIRECT, SamlBinding.ARTIFACT, false },
				{ SamlBinding.REDIRECT, SamlBinding.SOAP, false },
				// SOAP response not supported
				{ SamlBinding.SOAP, null, true },
				{ SamlBinding.SOAP, SamlBinding.SOAP, true },
				{ SamlBinding.SOAP, SamlBinding.REDIRECT, false },
				{ SamlBinding.SOAP, SamlBinding.POST, false },
				{ SamlBinding.SOAP, SamlBinding.ARTIFACT, false },
		};
	}

	@ParameterizedTest
	@MethodSource
	void ofSupportedString(String binding, SamlBinding expectedBinding) {
		assertThat(SamlBinding.of(binding), is(expectedBinding));
	}

	static Object[][] ofSupportedString() {
		return new Object[][] {
				{ null, null },
				{ SAMLConstants.SAML2_ARTIFACT_BINDING_URI, SamlBinding.ARTIFACT },
				{ SAMLConstants.SAML2_POST_BINDING_URI, SamlBinding.POST },
				{ SAMLConstants.SAML2_REDIRECT_BINDING_URI, SamlBinding.REDIRECT }
		};
	}

	@Test
	void ofUnsupportedString() {
		assertThrows(RequestDeniedException.class, () -> SamlBinding.of(SAMLConstants.SAML2_PAOS_BINDING_URI));
	}
}
