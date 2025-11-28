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

package swiss.trustbroker.federation.xmlconfig;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import swiss.trustbroker.common.saml.dto.SamlBinding;

class ArtifactBindingTest {

	@ParameterizedTest
	@MethodSource
	void useArtifactBinding(ArtifactBindingMode outbound,
			SamlBinding requestBinding, SamlBinding requestedResponseBinding, boolean expectedResult) {
		var artifactBinding = ArtifactBinding.builder()
											 .outboundMode(outbound)
											 .build();
		assertThat(artifactBinding.useArtifactBinding(requestBinding, requestedResponseBinding), is(expectedResult));
	}

	static Object[][] useArtifactBinding() {
		return new Object[][] {
				{ null, SamlBinding.POST, null, false },
				{ null, SamlBinding.ARTIFACT, null, false },
				{ ArtifactBindingMode.NOT_SUPPORTED, SamlBinding.ARTIFACT, null, false },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.POST, null, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.POST, null, false },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.REDIRECT, null, false },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.ARTIFACT, null, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.ARTIFACT, SamlBinding.POST, false }, // requested binding wins
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.ARTIFACT, SamlBinding.REDIRECT, false }, // requested binding wins
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.POST, SamlBinding.ARTIFACT, true }
		};
	}

	@ParameterizedTest
	@MethodSource
	void validInboundBinding(ArtifactBindingMode inbound, SamlBinding requestBinding, boolean expectedResult) {
		var artifactBinding = ArtifactBinding.builder()
											 .inboundMode(inbound)
											 .build();
		assertThat(artifactBinding.validInboundBinding(requestBinding), is(expectedResult));
	}

	static Object[][] validInboundBinding() {
		return new Object[][] {
				{ null, SamlBinding.POST, true },
				{ null, SamlBinding.REDIRECT, true },
				{ null, SamlBinding.ARTIFACT, true },
				{ ArtifactBindingMode.NOT_SUPPORTED, SamlBinding.POST, true },
				{ ArtifactBindingMode.NOT_SUPPORTED, SamlBinding.REDIRECT, true },
				{ ArtifactBindingMode.NOT_SUPPORTED, SamlBinding.ARTIFACT, false },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.POST, false },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.REDIRECT, false },
				{ ArtifactBindingMode.REQUIRED, SamlBinding.ARTIFACT, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.POST, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.REDIRECT, true },
				{ ArtifactBindingMode.SUPPORTED, SamlBinding.ARTIFACT, true }
		};
	}
}
