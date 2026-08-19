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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import javax.naming.directory.SearchControls;

import io.micrometer.core.annotation.Timed;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.text.StringSubstitutor;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.support.LdapEncoder;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;
import swiss.trustbroker.common.config.ExternalStores;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.tracing.Traced;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.ldap.model.LdapAttributeMapper;
import swiss.trustbroker.saml.dto.ClaimSource;

@Service
@Slf4j
@AllArgsConstructor
public class LdapClient {

	private static final String COLON = ":";
	private static final String SUBJECT_NAME_ID = "subjectNameId";
	private static final String PLACEHOLDER_PATTERN = "\\$\\{([^}]+)}";
	private static final String LIST_PLACEHOLDER = "LIST";

	private final LdapTemplate ldapTemplate;

	private final TrustBrokerProperties trustBrokerProperties;

	@Timed("ldap")
	@Traced
	public List<Map<String, List<String>>> search(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse, IdmRequest idmQuery,
	                                              List<Map<String, List<String>>> attributes, IdmResult result) {
		final var appFilter = idmQuery.getAppFilter();
		final var formattedQuery = queryFilterFormatter(appFilter, cpResponse, relyingPartyConfig.getId(), attributes, result);
		final var base = getQueryBase(idmQuery.getSubResource(), relyingPartyConfig);
		log.info("IDM call ({}): issuer={} relyingPartyIssuerId={} base={} query={} ",
				ExternalStores.LDAP, cpResponse.getIssuerId(), relyingPartyConfig.getId(), base, formattedQuery);
		final var attrs = ldapTemplate.search(base, formattedQuery, SearchControls.SUBTREE_SCOPE, new String[]{ "*" }, new LdapAttributeMapper());
		log.debug("IDM search ({}): for rp={} with query={} results={}", ExternalStores.LDAP, relyingPartyConfig.getId(), formattedQuery, attrs);

		return attrs;
	}

	String getQueryBase(String subResource, RelyingPartyConfig relyingPartyConfig) {
		if (subResource == null || subResource.isEmpty()) {
			throw new TechnicalException(String.format("Missing subResource for rp=%s HINT: Set RelyingParty.IDMLookup.IDMQuery.SubResource", relyingPartyConfig.getId()));
		}
		return subResource;
	}

	String queryFilterFormatter(String appFilter, CpResponseData cpResponse, String rpId, List<Map<String, List<String>>> attributes,
	                            IdmResult result) {
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
			if (placeholder == null) {
				log.error("Placeholder is null in appFilter={}", appFilter);
				continue;
			}
			var placeholderValues = getPlaceholderValues(placeholder, cpResponse, attributes, result);
			var placeholderValue = getEncodedPlaceHolderValue(placeholder, placeholderValues, ldapUndefined);
			params.put(placeholder, placeholderValue);
		}

		return StringSubstitutor.replace(appFilter, params, "${", "}");
	}

	static String getEncodedPlaceHolderValue(String placeholder, List<String> placeholderValues, String ldapUndefined) {
		var placeholderValue = new StringBuilder();

		if (placeholder.startsWith(LIST_PLACEHOLDER)) {
			var claimName = getListPlaceholderClaim(placeholder);
			for (String value : placeholderValues) {
				var encodedValue = LdapEncoder.filterEncode(value);
				placeholderValue.append('(').append(claimName).append("=").append(encodedValue).append(')');
			}
		}
		else if (!placeholderValues.isEmpty()) {
			if (placeholderValues.getFirst() == null) {
				return ldapUndefined;
			}
			return LdapEncoder.filterEncode(placeholderValues.getFirst());
		}
		else {
			throw new TechnicalException("Unsupported placeholder values: " + placeholderValues);
		}
		return placeholderValue.toString();
	}

	private static String getListPlaceholderClaim(String placeholder) {
		String[] elements = placeholder.split(COLON);
		if (elements.length != 4) {
			throw new TechnicalException("Expected LIST placeholder format: " + placeholder);
		}
		return elements[3];
	}

	List<String> getPlaceholderValues(String placeholder, CpResponseData cpResponse, List<Map<String, List<String>>> attributeNameListMap, IdmResult result) {
		if (placeholder == null) {
			return Collections.emptyList();
		}
		List<String> placeholderValues = new ArrayList<>();
		if (SUBJECT_NAME_ID.equals(placeholder)) {
			placeholderValues.add(cpResponse.getNameId());
		}
		else if (isIdmClaim(placeholder)) {
			return getUserDetails(placeholder, attributeNameListMap, result);
		}
		else if (isPropertiesClaim(placeholder)) {
			return getProperties(placeholder, result);
		}
		else {
			placeholderValues.add(cpResponse.getAttribute(placeholder));
		}
		return placeholderValues;
	}

	private List<String> getProperties(String placeholder, IdmResult result) {
		// Example: placeholder in form of `LIST:PROPS:<definition_name>` or `PROPS:<definition_name>`
		final var lastColonIndex = placeholder.lastIndexOf(COLON);
		final var claimName = placeholder.substring(lastColonIndex + 1);
		List<String> placeholderValues = new ArrayList<>();
		if (result == null || result.getProperties() == null || result.getProperties().isEmpty()) {
			placeholderValues.add(trustBrokerProperties.getLdap().getUndefined());
			return placeholderValues;
		}
		result.getUserDetails().forEach((key, value) -> {
			if (key != null && (claimName.equals(key.getName()) || claimName.equals(key.getNamespaceUri()))) {
				placeholderValues.addAll(value);
			}
		});
		return placeholderValues;
	}

	private static List<String> getAttributeFromListMap(String claimName, List<Map<String, List<String>>> attributes) {
		List<String> attributeValues = new ArrayList<>();
		for (var map : attributes) {
			if (map.containsKey(claimName)) {
				attributeValues.addAll(map.get(claimName));
			}
		}
		return attributeValues;
	}

	boolean isIdmClaim(String placeholder) {
		return isClaimSource(placeholder, ClaimSource.IDM);
	}

	boolean isPropertiesClaim(String placeholder) {
		return isClaimSource(placeholder, ClaimSource.PROPS);
	}

	private boolean isClaimSource(String placeholder, ClaimSource source) {
		var lastSeparator = placeholder.lastIndexOf(COLON);
		if (lastSeparator == -1) {
			return false;
		}
		var sourceIndex = placeholder.indexOf(source.name());
		return sourceIndex != -1 && sourceIndex < lastSeparator;
	}

	private List<String> getUserDetails(String placeholder, List<Map<String, List<String>>> attributeNameListMap, IdmResult result) {
		// Example: placeholder in form of `LIST:IDM:<query_name>:<definition_name>` or `IDM:<query_name>:<definition_name>`
		final var lastColonIndex = placeholder.lastIndexOf(COLON);
		final var claimName = placeholder.substring(lastColonIndex + 1);
		final var source = placeholder.substring(0, lastColonIndex);
		List<String> placeholderValues = new ArrayList<>();
		List<String> list = new ArrayList<>();
		if (source.contains(ExternalStores.LDAP.name())) {
			list = getAttributeFromListMap(claimName, attributeNameListMap);
			if (list.isEmpty()) {
				placeholderValues.add(trustBrokerProperties.getLdap().getUndefined());
				return placeholderValues;
			}

		}
		else {
			if (result == null || result.getUserDetails() == null || result.getUserDetails().isEmpty()) {
				placeholderValues.add(trustBrokerProperties.getLdap().getUndefined());
				return placeholderValues;
			}
			List<String> userDetails = new ArrayList<>();
			final var idmSource = source.contains(LIST_PLACEHOLDER) && source.split(COLON).length > 1 ? source.split(COLON)[1] : source;
			result.getUserDetails().forEach((key, value) -> {
				if (key != null) {
					boolean sameName = claimName.equals(key.getName()) || claimName.equals(key.getNamespaceUri());
					boolean sameSource = key.getSource() != null && key.getSource().equals(idmSource);
					if (sameName && sameSource) {
						userDetails.addAll(value);
					}
				}
			});
			if (!userDetails.isEmpty()) {
				list = userDetails;
			}
		}
		list = list.stream().distinct().toList();
		for (String claimValue : list) {
			placeholderValues.add(claimValue != null ? claimValue : trustBrokerProperties.getLdap().getUndefined());
		}
		return !placeholderValues.isEmpty() ? placeholderValues : List.of(trustBrokerProperties.getLdap().getUndefined());
	}

}
