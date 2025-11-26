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

package swiss.trustbroker.ldap.service;

import static org.springframework.core.Ordered.LOWEST_PRECEDENCE;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.directory.SearchControls;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmRequests;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.idm.service.IdmQueryService;
import swiss.trustbroker.api.idm.service.IdmStatusPolicyCallback;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.LdapStoreConfig;
import swiss.trustbroker.ldap.config.ExternalStores;
import swiss.trustbroker.ldap.model.LdapAttributeMapper;
import swiss.trustbroker.util.IdmAttributeUtil;

@Service
@Slf4j
@Order(LOWEST_PRECEDENCE)
public class LdapService implements IdmQueryService {

	private static final String COLON = ":";
	private static final String SUBJECT_NAME_ID = "subjectNameId";
	private static final String PLACEHOLDER_PATTERN = "\\$\\{([^}]+)}";
	private final LdapTemplate ldapTemplate;
	private final LdapStoreConfig ldapStoreConfig;

	@Autowired
	public LdapService(LdapTemplate ldapTemplate, TrustBrokerProperties trustBrokerProperties) {
		this.ldapTemplate = ldapTemplate;
		this.ldapStoreConfig = trustBrokerProperties.getLdap();
	}

	@Override
	public Optional<IdmResult> getAttributes(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse, IdmRequests idmRequests, IdmStatusPolicyCallback statusPolicyCallback) {
		final var requestedStore = ExternalStores.LDAP.name();
		if (!ldapStoreConfig.isEnabled() || !hasQueryOfStore(requestedStore, idmRequests, null)) {
			log.debug("Skipping idmService={} for idmRequests={}", ExternalStores.LDAP, idmRequests);
			return Optional.empty();
		}
		var result = getLdapAttributes(relyingPartyConfig, cpResponse, idmRequests);
		log.debug("LDAP result: attributeCount={} propertyCount={}",
				result.getUserDetails().size(), result.getProperties().size());
		return Optional.of(result);
	}

	private IdmResult getLdapAttributes(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse, IdmRequests idmRequests) {
		var result = new IdmResult();
		var attributeCount = 0;
		var querySuccessCount = 0;

		// iterate over all queries skipping all not addressed to store LDAP
		final var requestedStore = ExternalStores.LDAP.name();
		for (var idmQuery : idmRequests.getQueryList()) {
			if (!isQueryOfStore(requestedStore, idmQuery, idmRequests.getStore())) {
				log.debug("Skipping idmService={} for idmQuery={}", ExternalStores.LDAP, idmQuery);
				continue;
			}
			result.getQueriedStores().add(requestedStore);
			log.debug("LDAP call: issuer={} nameID={} relyingPartyIssuerId={}",
					cpResponse.getIssuerId(), cpResponse.getNameId(), relyingPartyConfig.getId());
			final var appFilter = idmQuery.getAppFilter();
			final var formattedQuery = queryFilterFormatter(appFilter, cpResponse);
			log.debug("LDAP Query Filter={}", formattedQuery);
			final var attrs = ldapTemplate.search(
					ldapStoreConfig.getSearchBase(),
					formattedQuery,
					SearchControls.SUBTREE_SCOPE,
					getAttributesToFetch(idmQuery),
					new LdapAttributeMapper()
			);
			log.debug("LDAP search results={}", attrs);

			if (!attrs.isEmpty()) {
				querySuccessCount += 1;
				final var attribute = aggregateAndFindAttributes(attrs, relyingPartyConfig, idmQuery);
				result.getUserDetails().putAll(attribute);
				attributeCount += attribute.size();
			}
		}

		if (log.isInfoEnabled()) {
			log.info("IDM result ({}): Called directory with issuer={} nameID={} "
							+ "queryCount={} successCount={} getting loginIds='{}', attributeCount={} and roleCount={}",
					ExternalStores.LDAP.name(), cpResponse.getIssuerId(), cpResponse.getNameId(),
					idmRequests.getQueryList().size(), querySuccessCount, List.of(), attributeCount, 0);
		}

		result.setOriginalUserDetailsCount(attributeCount);
		return result;
	}

	private String queryFilterFormatter(String appFilter, CpResponseData cpResponse) {
		// Extract placeholders
		Pattern pattern = Pattern.compile(PLACEHOLDER_PATTERN);
		Matcher matcher = pattern.matcher(appFilter);

		List<String> placeholders = new ArrayList<>();

		while (matcher.find()) {
			placeholders.add(matcher.group(1));
		}

		// Fill up placeholders
		Map<String, Object> params = new HashMap<>();

		for (var placeholder : placeholders) {
			params.put(placeholder, getPlaceholderValue(placeholder, cpResponse));
		}

		return StringSubstitutor.replace(appFilter, params, "${", "}");
	}

	private String getPlaceholderValue(String placeholder, CpResponseData cpResponse) {
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
		if (attributeSelection.isEmpty()){
			log.debug("Fetching all LDAP attributes.");
			return new String[]{"*"};
		}
		final var attrs = attributeSelection.stream().map(AttributeName::getName).toArray(String[]::new);
		log.debug("LDAP Attributes to fetch={}", CollectionUtil.toLogString(attrs));
		return attrs;
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

		List<AttributeName> attributeSelection = IdmAttributeUtil.getIdmAttributeSelection(relyingPartyConfig, idmQuery);
		return IdmAttributeUtil.getAttributesForQueryResponse(aggregatedAttributes, idmQuery.getName(), attributeSelection);
	}

	private boolean isChainedQuery(String placeholder) {
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
