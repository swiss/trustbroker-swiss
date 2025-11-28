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

package swiss.trustbroker.util;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import swiss.trustbroker.api.homerealmdiscovery.attributes.HrdClaimsProviderToRelyingPartyMapping;
import swiss.trustbroker.api.homerealmdiscovery.attributes.HrdHttpData;
import swiss.trustbroker.api.homerealmdiscovery.service.HrdService;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.oidc.session.HttpExchangeSupport;

/**
 * Log-able web input (where we do not expected any <i>StringUtil.clean</i> modified data) and other helpers.
 */
@Slf4j
public class HrdSupport {

	private HrdSupport() {
	}

	public static boolean requestFromTestApplication(HttpServletRequest request, TrustBrokerProperties properties) {
		return (getHrdHintTestCookie(request, properties) != null
				|| getHrdHintTestHeader(request, properties) != null)
				&& allowHrdHintTest(request, properties);
	}

	private static boolean allowHrdHintTest(HttpServletRequest request, TrustBrokerProperties properties) {
		return Boolean.TRUE.equals(properties.getHrdHintTestAllowedFromInternet())
				|| WebSupport.isClientOnIntranet(request, properties.getNetwork());
	}

	private static boolean hasAutoLoginDisabled(HttpServletRequest request, TrustBrokerProperties properties) {
		var autLoginCookie = properties.getPublicAutoLoginCookie();
		if (StringUtils.isNotEmpty(autLoginCookie)) {
			var cookieValue = WebUtil.getCookie(autLoginCookie, request);
			return "FALSE".equalsIgnoreCase(cookieValue); // true disables all HRD CP filtering
		}
		return false;
	}


	// Claims provider hints are used to do autoLogin routing to a preferred IDP without displaying an HRD screen
	public static String getClaimsProviderHint(HttpServletRequest request, TrustBrokerProperties properties) {
		if (request == null) {
			return null;
		}

		String cpSelection = null;
		var reason = "default";

		// Testing HRD hint: HTTP header or cookie signaling selected CP independent of network etc. required for automation
		if (allowHrdHintTest(request, properties)) {
			cpSelection = getHrdHintTestCookie(request, properties);
			reason = updateReason(cpSelection, properties.getHrdHintTestParameter() + " cookie", reason);
			if (cpSelection == null) {
				cpSelection = getHrdHintTestHeader(request, properties);
				reason = updateReason(cpSelection, properties.getHrdHintTestParameter() + " header", reason);
			}
		}

		// CP (IDP) hint: idp=xyz is supported there as a REST hint by applications
		if (cpSelection == null && getHrdHintParameter(request, properties) != null) {
			cpSelection = StringUtil.clean(getHrdHintParameter(request, properties));
			reason = updateReason(cpSelection, properties.getHrdHintParameter() + " parameter", reason);
		}

		// Testing hint: HTTP autoLogin cookie Disabling autoLogin behavior so testers can select CP manually
		if (cpSelection == null && hasAutoLoginDisabled(request, properties)) {
			log.debug("HRD detected {}=FALSE cookie signaling tester to select CP manually",
					properties.getPublicAutoLoginCookie());
			return null;
		}

		// Mobile hint: Using mobile GW/CP requires direct dispatching except when we already bailed out autoLogin=FALSE
		// In this case the mobile CP is displayed for testing purposes even though login is not possible.
		var clientIps = WebUtil.getGatewayIps(request);
		var gatewayIp = properties.getNetwork() != null ? properties.getNetwork().getMobileGatewayIpRegex() : null;
		if (cpSelection == null && StringUtils.isNotEmpty(gatewayIp) && isGateWayIp(clientIps, gatewayIp)) {
			cpSelection = properties.getMobileIdpId();
			reason = updateReason(cpSelection, "gatewayIPAddress=" + gatewayIp, reason);
		}

		// make network setup visible in context of HRD debugging
		if (log.isDebugEnabled()) {
			var clientNetwork = WebSupport.getClientNetwork(request, properties.getNetwork());
			log.debug("HRD routing hints lead to cpSelection={} with reason={} from clientNetwork={} clientIp={} gatewayIp={}",
					cpSelection, reason, clientNetwork, clientIps, gatewayIp);
		}
		return cpSelection;
	}

	public static String getHrdHintParameter(HttpServletRequest request, TrustBrokerProperties properties) {
		var hrdHintParameter = properties.getHrdHintParameter();
		if (StringUtils.isEmpty(hrdHintParameter)) {
			return null;
		}
		return WebUtil.getParameter(hrdHintParameter, request);
	}

	public static String getHrdHintTestCookie(HttpServletRequest request, TrustBrokerProperties properties) {
		var hrdHintParameter = properties.getHrdHintTestParameter();
		if (StringUtils.isEmpty(hrdHintParameter)) {
			return null;
		}
		return WebUtil.getCookie(hrdHintParameter, request);
	}

	public static String getHrdHintTestHeader(HttpServletRequest request, TrustBrokerProperties properties) {
		var hrdHintParameter = properties.getHrdHintTestParameter();
		if (StringUtils.isEmpty(hrdHintParameter)) {
			return null;
		}
		return WebUtil.getHeader(hrdHintParameter, request);
	}

	public static boolean isHrdHintTest(HttpServletRequest request, TrustBrokerProperties properties) {
		return getHrdHintTestCookie(request, properties) != null
				|| getHrdHintTestHeader(request, properties) != null;
	}

	private static boolean isGateWayIp(String[] clientIps, String gatewayIp) {
		for (var clientIp : clientIps) {
			if (clientIp.matches(gatewayIp)) {
				return true;
			}
		}
		return false;
	}

	public static boolean isXtbDestination(TrustBrokerProperties trustBrokerProperties, String destination) {
		if (destination == null || trustBrokerProperties.getOidc() == null
				|| trustBrokerProperties.getOidc().getPerimeterUrl() == null) {
			return false;
		}
		try {
			URI destinationUrl = new URI(destination);
			URI oidcPerimeterUrl = new URI(trustBrokerProperties.getOidc().getPerimeterUrl());
			if (destinationUrl.getHost() == null || oidcPerimeterUrl.getHost() == null) {
				return false;
			}
			return destinationUrl.getHost().equals(oidcPerimeterUrl.getHost());
		}
		catch (URISyntaxException ex) {
			throw new RequestDeniedException("Invalid URL", ex);
		}
	}

	private static String updateReason(String cpSelection, String override, String reason) {
		return cpSelection != null ? override : reason;
	}

	// OIDC routing variant when we have 3 copy&pasted SetupRP files not consolidated into a single one
	// Deprecate/discard this code as soon as all Oidc.Client are not distributed over multiple files anymore.
	public static String getClaimsProviderHint(TrustBrokerProperties properties) {
		var request = HttpExchangeSupport.getRunningHttpRequest();
		if (request == null) {
			return null;
		}
		var cpSelection = getClaimsProviderHint(request, properties);
		if (cpSelection == null && WebSupport.getClientNetwork(request, properties.getNetwork()) != null) {
			if (WebSupport.isClientOnIntranet(request, properties.getNetwork())) {
				cpSelection = properties.getEnterpriseIdpId();
			}
			else if (WebSupport.isClientOnInternet(request, properties.getNetwork())) {
				cpSelection = properties.getPublicIdpId();
			}
		}
		log.debug("HRD routing OIDC pre-selection lead to cpSelection={}", cpSelection);
		return cpSelection;
	}

	public static List<ClaimsProvider> reduceClaimsProviderMappings(
			HttpServletRequest request, String rpIssuer, String applicationName,
			String cpSelectionHint, List<ClaimsProvider> cpMappings,
			TrustBrokerProperties trustBrokerProperties,
			HrdService hrdService) {

		// bailout if we have only a single CP based on config or groovy scripting
		log.debug("HRD reduce start ({}): {}", cpMappings != null ? cpMappings.size() : 0, cpMappings);
		if (cpMappings == null || cpMappings.size() < 2) {
			return cpMappings;
		}

		// matching hint first as it should select an existing CP, and we are done including the mobile GW
		cpMappings = filterMappingsForHint(cpSelectionHint, cpMappings);

		// throw out all CPs not valid for current network (not applied if cpSelectionHint already chose aa single CP)
		cpMappings = filterMappingsForNetwork(request, cpMappings, trustBrokerProperties);

		// if autoLogin=FALSE cookie is present we keep all CPs for selection except if not allowed on the network before
		if (hasAutoLoginDisabled(request, trustBrokerProperties)) {
			return filterMappingDuplicates(cpMappings);
		}

		// pick an exact match of the alias using applName or OIDC client_id first, then SAML issuerID
		cpMappings = filterMappingsForRelyingPartyAlias(applicationName, cpMappings); // OIDC client_id
		cpMappings = filterMappingsForRelyingPartyAlias(rpIssuer, cpMappings); // SAML Issuer ID

		cpMappings = mapResultMappings(hrdService.adaptClaimsProviderMappings(HrdHttpData.of(request), cpMappings));

		// discard all remaining mappings with a relyingPartyAlias except if we only have such still
		cpMappings = filterMappingsForNonMatchingAliases(cpMappings);

		log.debug("HRD reduce end ({}): {}", cpMappings.size(), cpMappings);
		return cpMappings;
	}

	// map elements if they are not ClaimsProvider (just type conversion)
	private static List<ClaimsProvider> mapResultMappings(List<HrdClaimsProviderToRelyingPartyMapping> mappings) {
		List<ClaimsProvider> result = new ArrayList<>(mappings.size());
		for (var mapping : mappings) {
			result.add(ClaimsProvider.of(mapping));
		}
		return result;
	}

	private static List<ClaimsProvider> filterMappingDuplicates(List<ClaimsProvider> cpMappings) {
		var dedup = new LinkedHashMap<String, ClaimsProvider>(); // retain order
		cpMappings.forEach(m -> {
			var currentEntry = dedup.get(m.getId());
			if (currentEntry == null || m.getRelyingPartyAlias() == null) {
				currentEntry = dedup.put(m.getId(), m); // prefer plain entries over aliased ones
			}
			if (currentEntry != null) {
				log.debug("Dropped duplicate or aliased cpId={} relyingPartyAlias={}", m.getId(), m.getRelyingPartyAlias());
			}
		});
		log.debug("HRD de-duplicated ({} => {}): {}", cpMappings.size(), dedup.size(), dedup.values());
		return dedup.isEmpty() ? cpMappings : dedup.values().stream().toList();
	}

	private static List<ClaimsProvider> filterMappingsForHint(String cpSelectionHint,
                                                              List<ClaimsProvider> cpMappings) {
		if (cpMappings.size() < 2 || cpSelectionHint == null) {
			return cpMappings;
		}
		var selectedCp = cpMappings.stream().filter(cpm -> cpm.isMatchingHrdHint(cpSelectionHint)).toList();
		if (!selectedCp.isEmpty()) {
			var newList = new ArrayList<ClaimsProvider>(); // eliminate output duplicates
			newList.add(selectedCp.get(0));
			log.debug("HRD reduced by hint={} ({}): {}", cpSelectionHint, newList.size(), newList);
			return newList;
		}
		log.debug("HRD ignored invalid hint={}", cpSelectionHint);
		return cpMappings;
	}

	private static List<ClaimsProvider> filterMappingsForNetwork(HttpServletRequest request,
                                                                 List<ClaimsProvider> cpMappings, TrustBrokerProperties properties) {
		if (cpMappings.size() < 2) {
			return cpMappings;
		}
		var network = WebSupport.getClientNetwork(request, properties.getNetwork());
		if (network == null) {
			return cpMappings;
		}
		var networkHeader = properties.getNetwork() != null ? properties.getNetwork().getNetworkHeader() : null;
		var newList = new ArrayList<>(cpMappings.stream().filter(cpm -> cpm.isValidForNetwork(network)).toList());
		if (newList.isEmpty()) {
			throw new RequestDeniedException(String.format(
					"Got %s=%s but none of the configured cps are available on that network: %s",
					networkHeader, network, cpMappings));
		}
		log.debug("HRD reduced by network={} ({}): {}", network, newList.size(), newList);
		return newList;
	}

	private static List<ClaimsProvider> filterMappingsForRelyingPartyAlias(String rpOrAppId,
                                                                           List<ClaimsProvider> cpMappings) {
		if (cpMappings.size() < 2 || rpOrAppId == null) {
			return cpMappings;
		}
		var newList = new ArrayList<>(cpMappings.stream().filter(cpm -> cpm.isMatchingRelyingPartyAlias(rpOrAppId)).toList());
		var ret = newList.isEmpty() ? cpMappings : newList;
		log.debug("HRD reduced by rpOrAppId={} ({}): {}", rpOrAppId, ret.size(), ret);
		return ret;
	}

	private static List<ClaimsProvider> filterMappingsForNonMatchingAliases(
			List<ClaimsProvider> cpMappings) {
		if (cpMappings.size() < 2) {
			return cpMappings;
		}
		var newList = new ArrayList<>(cpMappings.stream().filter(cpm -> cpm.getRelyingPartyAlias() == null).toList());
		var ret = newList.isEmpty() ? cpMappings : newList;
		log.debug("HRD reduced by non-matching-aliases ({}): {}", ret.size(), ret);
		return ret;
	}

}
