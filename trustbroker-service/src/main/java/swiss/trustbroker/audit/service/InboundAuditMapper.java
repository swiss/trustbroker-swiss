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

package swiss.trustbroker.audit.service;

import java.util.HashMap;

import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.saml.dto.CpResponse;

public class InboundAuditMapper extends AuditMapper {

	public InboundAuditMapper(TrustBrokerProperties trustBrokerProperties) {
		super(trustBrokerProperties);
	}

	@Override
	protected AuditMapper mapAttributes(CpResponse cpResponse) {
		mapFromDefinitions(cpResponse.getAttributes(), AuditDto.AttributeSource.CP_RESPONSE); // filtered
		if (cpResponse.getOriginalAttributes() != null && !cpResponse.getOriginalAttributes().isEmpty()) {
			// log original attributes that have been dropped too because with XML encryption SAML-tracer does not help
			var originalAttributes = new HashMap<>(cpResponse.getOriginalAttributes());
			cpResponse.getAttributes().forEach((k, v) -> originalAttributes.remove(k));
			mapFromDefinitions(originalAttributes, AuditDto.AttributeSource.DROPPED_RESPONSE); // dropped
		}
		return this;
	}

	@Override
	protected AuditMapper mapClaims(CpResponse cpResponse) {
		return mapFromClaims(cpResponse.getClaims(), AuditDto.AttributeSource.OIDC_RESPONSE);
	}

}
