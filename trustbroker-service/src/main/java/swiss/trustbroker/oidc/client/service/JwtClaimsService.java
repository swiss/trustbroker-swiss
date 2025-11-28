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

package swiss.trustbroker.oidc.client.service;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;
import swiss.trustbroker.mapping.service.ClaimsMapperService;
import swiss.trustbroker.saml.dto.ClaimSource;

/**
 * Handles OIDC claims from a CP JWT token.
 */
@Service
@Slf4j
@AllArgsConstructor
public class JwtClaimsService {

	private ClaimsMapperService claimsMapperService;

	public List<String> getCtxClasses(JWTClaimsSet claims, ClaimsParty claimsParty) {
		var qoaClaim = getQoaClaim(claims, claimsParty);
		var contextClasses = convertClaimValues(null, qoaClaim);

		// Use default if CP did not send any
		if (contextClasses.isEmpty()) {
			contextClasses = getDefaultQoas(claimsParty);
		}

		log.debug("OIDC ACR claim resulted in contextClasses={}", contextClasses);
		return contextClasses;
	}

	private Object getQoaClaim(JWTClaimsSet claims, ClaimsParty claimsParty) {
		var qoaClaim = getConfiguredQoaClaim(claims, claimsParty);
		if (qoaClaim != null) {
			return qoaClaim;
		}

		// Use default to ACR claim
		qoaClaim = claims.getClaim(OidcUtil.OIDC_ACR);
		log.debug("Found OIDC ACR claim {}={}", OidcUtil.OIDC_ACR, qoaClaim);
		return qoaClaim;
	}

	// Check if there is a non-standard claim to use
	private Object getConfiguredQoaClaim(JWTClaimsSet claims, ClaimsParty claimsParty) {
		var qoa = claimsParty.getQoa();
		var qoaClaimName = qoa != null ? qoa.getClaim() : null;
		if (qoaClaimName == null) {
			return null;
		}
		var qoaClaim = claims.getClaim(qoaClaimName);
		log.debug("Found OIDC ACR claim from CP config {}={}", qoaClaimName, qoaClaim);
		return qoaClaim;
	}

	private List<String> getDefaultQoas(ClaimsParty claimsParty) {
		var qoa = claimsParty.getQoa();
		var defaultQoa = qoa != null ? qoa.getDefaultQoa() : null;
		log.debug("Using defaultQoa={}", defaultQoa);
		return defaultQoa != null ? List.of(defaultQoa) : Collections.emptyList();
	}

	public Map<Definition, List<String>> mapClaimsToAttributes(JWTClaimsSet claims, ClaimsParty claimsParty) {
		Map<Definition, List<String>> attributes = new HashMap<>();
		if (claimsParty.getAttributesSelection() == null
				|| CollectionUtils.isEmpty(claimsParty.getAttributesSelection().getDefinitions())) {
			return attributes;
		}
		var cpAttributeDefinitions = claimsParty.getAttributesSelection().getDefinitions();
		for (var claim : claims.getClaims().entrySet()) {
			var name = claim.getKey();
			var def = DefinitionUtil.findSingleValueByNameOrNamespace(name, null, cpAttributeDefinitions);
			var definition = def.orElseGet(() -> Definition.ofNameAndSource(name, ClaimSource.CP.name()));
			attributes.put(definition, convertClaimValues(definition, claim.getValue()));
		}
		return attributes;
	}

	private List<String> convertClaimValues(Definition definition, Object claimValue) {
		List<?> claimValues;
		if (claimValue instanceof List<?> claimList) {
			claimValues = claimList;
		}
		else if (claimValue == null) {
			claimValues = Collections.emptyList();
		}
		else {
			claimValues = List.of(claimValue);
		}
		if (definition != null) {
			claimValues = claimsMapperService.applyMappers(definition, claimValues, "OIDC claims");
		}
		return CollectionUtil.toStringList(claimValues, Object::toString);
	}

}
