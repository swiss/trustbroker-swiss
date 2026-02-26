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

package swiss.trustbroker.ldap.service;

import static org.springframework.core.Ordered.LOWEST_PRECEDENCE;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.naming.directory.SearchControls;

import io.micrometer.core.annotation.Timed;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.core.annotation.Order;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapEncoder;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmRequests;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.api.idm.service.IdmStatusPolicyCallback;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.tracing.Traced;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ProfileSelection;
import swiss.trustbroker.federation.xmlconfig.ProfileSelectionMode;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.ldap.model.LdapAttributeMapper;
import swiss.trustbroker.util.IdmAttributeUtil;

@Service
@Slf4j
@Order(LOWEST_PRECEDENCE)
@AllArgsConstructor
public class LdapService implements IdmQueryService {

	private static final String COLON = ":";
	private static final String SUBJECT_NAME_ID = "subjectNameId";
	private static final String PLACEHOLDER_PATTERN = "\\$\\{([^}]+)}";
	private static final String DEFAULT_PROFILE_SEPARATOR = "\\";

	private final LdapTemplate ldapTemplate;

	private final TrustBrokerProperties trustBrokerProperties;

	@Override
	public Optional<IdmResult> getAttributes(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse, IdmRequests idmRequests, IdmStatusPolicyCallback statusPolicyCallback) {
		final var requestedStore = ExternalStores.LDAP.name();
		var ldapStoreConfig = trustBrokerProperties.getLdap();
		if (!ldapStoreConfig.isEnabled() || !hasQueryOfStore(requestedStore, idmRequests, null)) {
			log.trace("Skipping idmService={} for idmRequests={}", ExternalStores.LDAP, idmRequests);
			return Optional.empty();
		}
		var result = getLdapAttributes(relyingPartyConfig, cpResponse, idmRequests);
		log.info("LDAP result: attributeCount={} propertyCount={}", result.getUserDetails().size(), result.getProperties().size());
		return Optional.of(result);
	}

	@Timed("ldap")
	@Traced
	IdmResult getLdapAttributes(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse, IdmRequests idmRequests) {
		var result = new IdmResult();
		var attributeCount = 0;
		var querySuccessCount = 0;

		// iterate over all queries skipping all not addressed to store LDAP
		final var requestedStore = ExternalStores.LDAP.name();
		for (var idmQuery : idmRequests.getQueryList()) {
			if (!isQueryOfStore(requestedStore, idmQuery, idmRequests.getStore())) {
				log.trace("Skipping idmService={} for idmQuery={}", ExternalStores.LDAP, idmQuery);
				continue;
			}
			result.getQueriedStores().add(requestedStore);
			final var appFilter = idmQuery.getAppFilter();
			final var formattedQuery = queryFilterFormatter(appFilter, cpResponse, relyingPartyConfig.getId());
			final var base = getQueryBase(idmQuery.getSubResource(), relyingPartyConfig);
			log.debug("LDAP call: issuer={} relyingPartyIssuerId={} base={} query={} ",
					cpResponse.getIssuerId(), relyingPartyConfig.getId(), base, formattedQuery);
			final var attrs = ldapTemplate.search(base, formattedQuery, SearchControls.SUBTREE_SCOPE,
					getAttributesToFetch(idmQuery), new LdapAttributeMapper());
			log.debug("LDAP search result for rp={} with query={} results={}", relyingPartyConfig.getId(), formattedQuery, attrs);

			if (!attrs.isEmpty()) {
				querySuccessCount += 1;
				final var profileSelectionProperties = ((RelyingParty) relyingPartyConfig).getProfileSelection();
				if (profileSelectionProperties != null && profileSelectionProperties.isProfileSelectionEnabled() &&
						!ProfileSelectionMode.SILENT.name().equals(profileSelectionProperties.getProfileSelectionMode())) {
					prefixProfileAttributes(relyingPartyConfig, profileSelectionProperties, attrs);
				}
				final var attributes = aggregateAndFindAttributes(attrs, relyingPartyConfig, idmQuery);
				result.getUserDetails().putAll(attributes);
				attributeCount += attributes.size();
			}
		}

		if (log.isInfoEnabled()) {
			log.info("IDM result ({}): Called directory with issuer={} nameID={} queryCount={} successCount={}",
					ExternalStores.LDAP.name(), cpResponse.getIssuerId(), cpResponse.getNameId(),
					idmRequests.getQueryList().size(), querySuccessCount);
		}

		result.setOriginalUserDetailsCount(attributeCount);
		return result;
	}

	String getQueryBase(String subResource, RelyingPartyConfig relyingPartyConfig) {
		if (subResource == null || subResource.isEmpty()) {
			throw new TechnicalException(String.format("Missing subResource for rp=%s HINT: Set RelyingParty.IDMLookup.IDMQuery.SubResource", relyingPartyConfig.getId()));
		}
		return subResource;
	}

	void prefixProfileAttributes(RelyingPartyConfig relyingPartyConfig, ProfileSelection profileSelectionProperties, List<Map<String, List<String>>> attrs) {
		final var profileSelector = getProfileSelector(profileSelectionProperties, relyingPartyConfig.getId());
		if (!userWithMultiProfiles(attrs, profileSelector)) {
			return;
		}
		for (var profile : attrs) {
			// no such an attribute in LDAP result
			if (profile.get(profileSelector) == null) {
				throw new TechnicalException(String.format("ProfileSelection.profileSelector=%s attributes not found for rpId=%s",
						profileSelector, relyingPartyConfig.getId()));
			}
			final var profileSelectorValue = profile.get(profileSelector).get(0);
			prefixValuesWithProfileSelector(profileSelectorValue, profileSelector, profile);
		}
	}

	boolean userWithMultiProfiles(List<Map<String, List<String>>> attrs, String profileSelector) {
		if (profileSelector == null) {
			return false;
		}

		// profileSelector must be a unique attribute in LDAP
		var userProfiles = attrs.stream().filter(attr -> attr.containsKey(profileSelector))
								.flatMap(attr -> attr.get(profileSelector).stream()).collect(Collectors.toSet());
		return userProfiles.size() > 1;
	}

	String queryFilterFormatter(String appFilter, CpResponseData cpResponse, String rpId) {
		if (appFilter == null || appFilter.isEmpty()) {
			throw new TechnicalException(String.format(
					"AppFilter is null or empty for rp=%s HINT: configure IDMLookup.IDMQuery.AppFilter", rpId));
		}
		var ldapUndefined = trustBrokerProperties.getLdap().getUndefined();
		// Extract placeholders
		var pattern = Pattern.compile(PLACEHOLDER_PATTERN);
		var matcher = pattern.matcher(appFilter);

		List<String> placeholders = new ArrayList<>();

		while (matcher.find()) {
			placeholders.add(matcher.group(1));
		}

		// Fill up placeholders
		Map<String, Object> params = new HashMap<>();

		for (var placeholder : placeholders) {
			var placeholderValue = getPlaceholderValue(placeholder, cpResponse);
			if (placeholderValue == null && ldapUndefined != null) {
				placeholderValue = ldapUndefined;

			}
			params.put(placeholder, LdapEncoder.filterEncode(placeholderValue));
		}

		return StringSubstitutor.replace(appFilter, params, "${", "}");
	}

	String getPlaceholderValue(String placeholder, CpResponseData cpResponse) {
		if (SUBJECT_NAME_ID.equals(placeholder)) {
			return cpResponse.getNameId();
		}
		else if (isChainedQuery(placeholder)) {
			return getUserDetail(placeholder, cpResponse);
		}
		else {
			return cpResponse.getAttribute(placeholder);
		}
	}

	private String[] getAttributesToFetch(IdmRequest idmQuery) {
		final var attributeSelection = idmQuery.getAttributeSelection();
		log.debug("Number of attributes to be fetch from LDAP={}", attributeSelection.size());
		if (attributeSelection.isEmpty()) {
			return new String[]{ "*" };
		}
		return attributeSelection.stream().map(AttributeName::getName).toArray(String[]::new);
	}

	String getProfileSelector(ProfileSelection profileSelectionProperties, String rpId) {
		final var profileSelector = profileSelectionProperties.getProfileSelector();
		if (profileSelector != null && !profileSelector.isEmpty()) {
			log.debug("LDAP Profile Selection for rp={}: using profileSelector={}", rpId, profileSelector);
			return profileSelector;
		}
		throw new TechnicalException(String.format(
				"LDAP ProfileSelection.profileSelector cannot be null or empty for rp=%s. HINT: set RelyingParty.ProfileSelection.profileSelector", rpId));
	}

	void prefixValuesWithProfileSelector(String profileSelectorValue, String exclude, Map<String, List<String>> profile) {
		if (profileSelectorValue == null) {
			log.warn("Profile Selection of LDAP wrongly configured. Missing ProfileSelection.profileSelector={}. HINT: set RelyingParty.ProfileSelection.profileSelector", exclude);
			return;
		}

		profile.replaceAll((key, values) -> key.equals(exclude) || values == null ?
				values : values.stream().map(value -> profileSelectorValue + DEFAULT_PROFILE_SEPARATOR + value).toList());
	}

	private Map<AttributeName, List<String>> aggregateAndFindAttributes(List<Map<String, List<String>>> attrs,
																		RelyingPartyConfig relyingPartyConfig,
																		IdmRequest idmQuery) {
		Map<String, List<String>> aggregatedAttributes = new HashMap<>();

		for (var attrMap : attrs) {
			for (Map.Entry<String, List<String>> entry : attrMap.entrySet()) {
				aggregatedAttributes
						.computeIfAbsent(entry.getKey(), k -> new ArrayList<>())
						.addAll(entry.getValue());
			}
		}

		// a wrong LDAP filter can lead to duplicated attributes in the attributes
		for (Map.Entry<String, List<String>> entry : aggregatedAttributes.entrySet()) {
			var deduplicated = new ArrayList<>(new HashSet<>(entry.getValue()));
			entry.setValue(deduplicated);
		}

		var attributeSelection = IdmAttributeUtil.getIdmAttributeSelection(relyingPartyConfig, idmQuery);
		return IdmAttributeUtil.getAttributesForQueryResponse(aggregatedAttributes, idmQuery.getName(), attributeSelection);
	}

	boolean isChainedQuery(String placeholder) {
		return placeholder.lastIndexOf(COLON) != -1;
	}

	private String getUserDetail(String placeholder, CpResponseData cpResponse) {
		// Example: placeholder in form of `IDM:<query_name>:<definition_name>`
		final var lastColonIndex = placeholder.lastIndexOf(COLON);
		final var claimName = placeholder.substring(lastColonIndex + 1);
		final var source = placeholder.substring(0, lastColonIndex);
		return cpResponse.getUserDetail(claimName, source);
	}

}
