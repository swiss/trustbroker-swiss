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

package swiss.trustbroker.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.mapping.util.AttributeFilterUtil;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.util.ClaimSourceUtil;

@Slf4j
public class IdmAttributeUtil {

	private IdmAttributeUtil() {
	}

	public static Map<AttributeName, List<String>> getAttributesForQueryResponse(Map<String, List<String>> attributes,
																				 String queryName, List<AttributeName> userDetailSelection) {
		Map<AttributeName, List<String>> result = new HashMap<>();

		// If attribute was not found in the AttributeName still keep it
		for (var map : attributes.entrySet()) {
			var definitionForKey = findDefinitionForKey(map.getKey(), userDetailSelection);
			var nameSpaceUri = definitionForKey != null ? definitionForKey.getNamespaceUri(): null;
			var mappers = definitionForKey instanceof Definition definition ? definition.getMappers(): null;
			var source = ClaimSourceUtil.buildClaimSource(ClaimSource.IDM, queryName);
			var attributeDef = Definition.builder()
					.name(map.getKey())
					.namespaceUri(nameSpaceUri)
					.mappers(mappers)
					.source(source).build();
			result.put(attributeDef, map.getValue());
		}
		// make picked data visible because filtering applied within IdmService hides it from script hooks
		if (log.isDebugEnabled()) {
			log.debug("Selected userDetails='{}' from queryName={} allUserDetails='{}'", result, attributes, queryName);
		}
		return result;
	}
	private static AttributeName findDefinitionForKey(String defName, List<AttributeName> attributes) {
		return attributes.stream()
				.filter(attribute -> defName.equals(attribute.getName()) && attribute.getNamespaceUri() != null)
				.findFirst()
				.orElse(null);
	}

	public static List<AttributeName> getIdmAttributeSelection(RelyingPartyConfig relyingPartyConfig, IdmRequest idmQuery) {
		if (relyingPartyConfig instanceof RelyingParty relyingParty) {
			var claimsSelection = AttributeFilterUtil.getClaimsForSource(relyingParty.getClaimsSelection(),
					ClaimSourceUtil.buildClaimSource(ClaimSource.IDM, idmQuery.getName()));
			return AttributeFilterUtil.joinConfAttributes(idmQuery.getAttributeSelection(), claimsSelection);
		}
		return new ArrayList<>(idmQuery.getAttributeSelection());
	}

	public static Map<String, List<Object>> getAttributesFromUserDetails(Map<Definition, List<String>> userDetails) {
		Map<String, List<Object>> attributes = new HashMap<>();
		for (Map.Entry<Definition, List<String>> entry : userDetails.entrySet()) {
			var definition = entry.getKey();
			var name = definition.getNamespaceUri() != null ? definition.getNamespaceUri() : definition.getName();
			if (attributes.containsKey(name)) {
				var differentValues = differentValues(attributes.get(name), entry.getValue());
				if (!differentValues.isEmpty()) {
					attributes.get(name).addAll(differentValues);
				}
			}
			else if (name != null || entry.getValue() != null) {
				List<Object> value = new ArrayList<>(entry.getValue());
				attributes.put(name, value);
			}
		}
		return attributes;
	}

	private static List<Object> differentValues(List<Object> objects, List<String> values) {
		List<Object> result = new ArrayList<>();
		for (var value : values) {
			if (!objects.contains(value)) {
				result.add(value);
			}
		}
		return result;
	}
}
