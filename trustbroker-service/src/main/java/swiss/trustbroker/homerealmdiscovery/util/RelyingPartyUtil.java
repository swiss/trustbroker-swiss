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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.api.idm.service.IdmStatusPolicyCallback;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.util.ConfigUtil;
import swiss.trustbroker.federation.xmlconfig.AttributesSelection;
import swiss.trustbroker.federation.xmlconfig.ClaimsProvider;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.saml.dto.CpResponse;

@Slf4j
public class RelyingPartyUtil {

	private RelyingPartyUtil() {}

	// Implements the referrer addressing approach.
	// Clients can be identified in configuration via the host:port/path of their referer header, not the URN in AuthnRequest
	public static List<String> getIdsFromReferer(String refererUrl) {
		List<String> refererIds = new ArrayList<>();
		if (refererUrl != null && (refererUrl.startsWith("http://") || refererUrl.startsWith("https://"))) {
			refererIds.add(refererUrl);
			refererUrl = refererUrl.replaceAll("\\?.*", "");    // cut query
			var urlParts = refererUrl.split("/");
			if (urlParts.length >= 5) {
				refererIds.add(urlParts[2] + "/" + urlParts[3] + "/" + urlParts[4]); // host:port/path/path
			}
			if (urlParts.length >= 4) {
				refererIds.add(urlParts[2] + "/" + urlParts[3]); // host:port/path
			}
			if (urlParts.length >= 3) {
				refererIds.add(urlParts[2]); // host:port
			}
		}
		return refererIds;
	}

	public static String getApplicationFromProfiledRole(String profiledRole) {
		// profileId\role
		String[] attributes = profiledRole.split("\\\\");
		if (attributes.length > 1) {
			return attributes[1];
		}
		return profiledRole;
	}

	public static Set<String> getCpIdsWithoutSpecChars(RelyingParty relyingParty) {
		List<ClaimsProvider> claimsProviderList = relyingParty.getClaimsProviderMappings().getClaimsProviderList();
		return claimsProviderList.stream()
								 .filter(claimsProvider -> claimsProvider.getId() != null)
								 .map(claimsProvider ->
								 {
									 var id = claimsProvider.getId();
									 return ConfigUtil.removeIdSpecChar(id);
								 })
								 .collect(Collectors.toSet());
	}

	public static void validateRequiredDefinitions(AttributesSelection attributesSelection, Map<Definition, List<String>> attributes) {
		if (attributesSelection == null) {
			return;
		}
		for (Definition definition : attributesSelection.getDefinitions()) {
			if (!attributes.containsKey(definition) && Boolean.TRUE.equals(definition.getRequired())) {
				throw new TechnicalException(String.format("Missing attribute in source=CP required by definition='%s'", definition));
			}
		}
	}

	public static Optional<IdmResult> performIdmLookups(CpResponse cpResponse, RelyingParty relyingParty, boolean audited,
			IdmStatusPolicyCallback statusPolicyCallback, List<IdmQueryService> idmQueryServices) {
		var idmLookup = cpResponse.getIdmLookup();
		if (idmLookup == null) {
			idmLookup = relyingParty.getIdmLookup();
			log.info("CpResponse has no IdmLookup - falling back to RpIssuerId={}", relyingParty.getId());
		}
		if (idmLookup != null && idmLookup.getQueries() != null) {
			return performIdmLookup(cpResponse, relyingParty, audited, statusPolicyCallback, idmQueryServices, idmLookup);
		}
		else {
			log.debug("RpIssuerId={} has no IdmLookup", relyingParty.getId());
		}
		return Optional.empty();
	}

	private static Optional<IdmResult> performIdmLookup(CpResponse cpResponse, RelyingParty relyingParty, boolean audited,
			IdmStatusPolicyCallback statusPolicyCallback, List<IdmQueryService> idmQueryServices, IdmLookup idmLookup) {
		Map<IdmQueryService, Map<String, Object>> overallState = new HashMap<>();
		var result = new IdmResult();
		var anyQueryDone = false;
		for (var query : idmLookup.getQueries()) {
			var idmServiceOpt = getServiceForStore(query, idmLookup.getStore(), idmQueryServices);
			if (idmServiceOpt.isEmpty()) {
				// Static configuration error would have been caught during set-up, script error must fail fast too
				throw new TechnicalException(String.format("Unable to find IdmQueryService for rpIssuerId=%s query=%s with "
								+ "store=%s - check IdmLookup modifications in scripts",
						relyingParty.getId(), query.getId(), query.getStore()));
			}
			var idmService = idmServiceOpt.get();
			var state = overallState.computeIfAbsent(idmService, key -> new HashMap<>());
			log.debug("RpIssuerId={} - calling audited={} query={} with store={}",
					relyingParty.getId(), audited, query.getId(), idmService.getStoreName());
			var queryDone = audited ?
					idmService.getAttributesAudited(relyingParty, cpResponse, query, statusPolicyCallback, state, result) :
					idmService.getAttributes(relyingParty, cpResponse, query, statusPolicyCallback, state, result);
			if (queryDone) {
				result.getQueriedStores().add(idmService.getStoreName());
				anyQueryDone = true;
			}
		}
		if (anyQueryDone) {
			log.debug("Returning IdmLookup result from stores={}", result.getQueriedStores());
			return Optional.of(result);
		}
		else {
			log.debug("RpIssuerId={} IdmLookup did not execute any queries", relyingParty.getId());
		}
		return Optional.empty();
	}

	public static Optional<IdmQueryService> getServiceForStore(
			IdmQuery query, String defaultStore, List<IdmQueryService> idmQueryServices) {
		if (CollectionUtils.isEmpty(idmQueryServices)) {
			return Optional.empty();
		}
		var store = getStore(query, defaultStore, idmQueryServices);
		return idmQueryServices.stream().filter(idmQueryService -> idmQueryService.getStoreName().equals(store)).findFirst();
	}

	private static String getStore(IdmQuery query, String defaultStore, List<IdmQueryService> idmQueryServices) {
		if (query.getStore() != null) {
			return query.getStore();
		}
		if (defaultStore != null) {
			log.debug("Defaulting to store={}", defaultStore);
			return defaultStore;
		}
		var store = idmQueryServices.stream().min(Comparator.comparing(IdmQueryService::getServiceDefaultOrder));
		var storeName = store.get().getStoreName();
		log.debug("Defaulting to minimum order store={}", storeName);
		return storeName;
	}

}
