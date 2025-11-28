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

import lombok.Builder;
import lombok.Data;
import lombok.NonNull;

@Builder
@Data
public class SignatureContext {

	@NonNull
	private SamlBinding binding;

	@Builder.Default
	private boolean requireSignature = true;

	// required for validation of inbound REDIRECT binding requests - path and query string only
	private String requestUrl;

	public static SignatureContext forRedirectBinding(String requestUrl) {
		return SignatureContext.builder()
				.binding(SamlBinding.REDIRECT)
				.requestUrl(requestUrl)
				.build();
	}

	public static SignatureContext forPostBinding() {
		return SignatureContext.builder()
				.binding(SamlBinding.POST)
				.build();
	}

	public static SignatureContext forArtifactBinding() {
		return SignatureContext.builder()
				.binding(SamlBinding.ARTIFACT)
				.build();
	}

	public static SignatureContext forSoapBinding() {
		return SignatureContext.builder()
				   .binding(SamlBinding.SOAP)
				   .build();
	}

	public static SignatureContext forBinding(SamlBinding binding, String requestUrl) {
		return switch (binding) {
			case REDIRECT -> SignatureContext.forRedirectBinding(requestUrl);
			case POST -> SignatureContext.forPostBinding();
			case ARTIFACT -> SignatureContext.forArtifactBinding();
			case SOAP -> SignatureContext.forSoapBinding();
		};
	}
}
