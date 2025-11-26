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

package swiss.trustbroker.oidc;

import java.util.Collections;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.util.FrameAncestorHandler;

@AllArgsConstructor
@Slf4j
public class OidcFrameAncestorHandler implements FrameAncestorHandler {

	private static final String APPLIED_FRAME_ANCESTORS = "AppliedFrameAncestors";

	private final HttpServletRequest request;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final TrustBrokerProperties trustBrokerProperties;

	@Override
	public List<String> supportedFrameAncestors() {
		var oidcClientId = OidcSessionSupport.getOidcClientId(
				request, relyingPartyDefinitions, trustBrokerProperties.getNetwork());
		if (oidcClientId == null) {
			return Collections.emptyList();
		}
		var oidcClient = relyingPartyDefinitions.getOidcClientConfigById(oidcClientId, trustBrokerProperties);
		if (oidcClient.isEmpty()) {
			return Collections.emptyList();
		}
		var acWhitelist = oidcClient.get().getRedirectUris();
		if (acWhitelist == null) {
			return Collections.emptyList();
		}
		var frameAncestors = acWhitelist.getFrameAncestorsWithFallback();
		if (CollectionUtils.isEmpty(frameAncestors)) {
			return Collections.emptyList();
		}
		log.debug("oidcClientId={} using CSP frame-ancestors={}", oidcClient.get().getId(), frameAncestors);
		return frameAncestors;
	}

	@Override
	public void appliedFrameAncestors(List<String> appliedFrameAncestors) {
		if (!CollectionUtils.isEmpty(appliedFrameAncestors)) {
			log.debug("Applied frameAncestors={}", appliedFrameAncestors);
			request.setAttribute(APPLIED_FRAME_ANCESTORS, appliedFrameAncestors);
		}
	}

	public boolean hasAppliedFrameAncestors() {
		return request.getAttribute(APPLIED_FRAME_ANCESTORS) != null;
	}
}
