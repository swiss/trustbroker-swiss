/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.saml.dto.RpRequest;
import swiss.trustbroker.util.WebSupport;

@Slf4j
public class OperationalUtil {

	private OperationalUtil() {}

	// OCC workaround for E2E monitoring robot mainly
	public static boolean useSkinnyUiForLegacyClients(RpRequest rpRequest, HttpServletRequest httpRequest,
			TrustBrokerProperties trustBrokerProperties) {
		// by BeforeHrd script e.g. for SPS19 using old MSIE sub-system
		if (rpRequest != null && rpRequest.isUseSkinnyHrdScreen()) {
			return true;
		}
		// by config from HTTP request e.g. for OCC E2E monitoring robot using old MSIE sub-system
		var skinnyUiTriggers = trustBrokerProperties.getSkinnyHrdTriggers();
		if (skinnyUiTriggers != null) {
			for (var skinnyUiTrigger : skinnyUiTriggers) {
				var header = skinnyUiTrigger.getName();
				var regexp = skinnyUiTrigger.getPattern();
				var headerValue = WebUtil.getHeader(header, httpRequest);
				if (headerValue != null && regexp.matcher(headerValue).matches()) {
					// we do this in DEBUG because too many clients will use this UI per request (OCC monitor, Office365 users)
					log.debug("Technical debt legacy using MSIE skinny HRD (no announcements support, no profile selection etc on {}",
							WebSupport.getClientHint(httpRequest, trustBrokerProperties.getNetwork()));
					return true;
				}
			}
		}
		return false;
	}

	// OCC workaround for E2E monitoring robot mainly and also for administrators
	public static boolean skipUiFeaturesForAdminAndMonitoringClients(HttpServletRequest httpRequest,
			TrustBrokerProperties trustBrokerProperties) {
		final var monitoringHints = trustBrokerProperties.getMonitoringHints();
		if (monitoringHints != null) {
			for (var monitoringHint : monitoringHints) {
				var header = monitoringHint.getName();
				var regexp = monitoringHint.getPattern();
				var headerValue = WebUtil.getHeader(header, httpRequest);
				if (headerValue != null && regexp.matcher(headerValue).matches()) {
					log.info("Skip UI Features because of existing Header={}", headerValue);
					return true;
				}
			}
		}
		return WebSupport.isAdminLogin(httpRequest);
	}

	// Skipping user feature means we are not displayed certain things like announcements and HRD screen with some advanced
	// features like disabling etc
	public static boolean skipUserFeatures(RpRequest rpRequest, HttpServletRequest httpRequest,
			TrustBrokerProperties trustBrokerProperties) {
		return skipUiFeaturesForAdminAndMonitoringClients(httpRequest, trustBrokerProperties)
				|| useSkinnyUiForLegacyClients(rpRequest, httpRequest, trustBrokerProperties);
	}

}
