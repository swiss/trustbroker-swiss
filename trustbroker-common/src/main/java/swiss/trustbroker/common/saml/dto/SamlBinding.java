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

import java.util.Collections;
import java.util.List;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.common.xml.SAMLConstants;
import swiss.trustbroker.common.exception.RequestDeniedException;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
@Slf4j
public enum SamlBinding {
	REDIRECT(SAMLConstants.SAML2_REDIRECT_BINDING_URI, Collections.emptyList()),
	// Response is never sent as REDIRECT (length restrictions)
	POST(SAMLConstants.SAML2_POST_BINDING_URI, List.of(REDIRECT)),
	// Response is never sent as REDIRECT (length restrictions), ARTIFACT is better than POST
	ARTIFACT(SAMLConstants.SAML2_ARTIFACT_BINDING_URI, List.of(POST, REDIRECT)),
	SOAP(SAMLConstants.SAML2_SOAP11_BINDING_URI, Collections.emptyList());

	private final String bindingUri;

	private final List<SamlBinding> compatibleRequestBindings;

	public boolean compatibleWithRequestedBinding(SamlBinding requestedBinding) {
		if (requestedBinding == null || this == requestedBinding) {
			log.debug("Correct response binding={} for requested protocolBinding={}", this, requestedBinding);
			return true;
		}
		if (compatibleRequestBindings.contains(requestedBinding)) {
			log.info("Accepting responseBinding={} for requested protocolBinding={}", this, requestedBinding);
			return true;
		}
		log.debug("Wrong responseBinding={} for requested protocolBinding={}", this, requestedBinding);
		return false;
	}

	// throws RequestDeniedException if not found
	public static SamlBinding of(String protocolBinding) {
		if (protocolBinding == null) {
			return null;
		}
		for (var binding : values()) {
			if (binding.bindingUri.equals(protocolBinding)) {
				return binding;
			}
		}
		throw new RequestDeniedException(String.format("Unsupported protocolBinding=%s", protocolBinding));
	}

	// test without exception
	public boolean is(String protocolBinding) {
		return bindingUri.equals(protocolBinding);
	}

	// for enabling checks
	public boolean isIn(List<String> protocolBindings) {
		return protocolBindings != null && protocolBindings.contains(bindingUri);
	}

	// flag conversion - trustbroker-api is not using this class, else it would become an API too
	public static SamlBinding of(boolean useArtifactBinding, boolean useRedirectBinding) {
		if (useArtifactBinding) {
			return SamlBinding.ARTIFACT;
		}
		if (useRedirectBinding) {
			return SamlBinding.REDIRECT;
		}
		return SamlBinding.POST;
	}

}
