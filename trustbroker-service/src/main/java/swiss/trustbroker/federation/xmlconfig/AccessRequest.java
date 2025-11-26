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

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;
import java.util.Collections;
import java.util.Map;
import java.util.stream.Collectors;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.lang3.tuple.Pair;

/**
 * This class describes the configuration of the AccessRequest for an RP.
 *
 * @see swiss.trustbroker.api.accessrequest.service.AccessRequestService
 */
@XmlRootElement(name = "AccessRequest")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessRequest implements Serializable {

	/**
	 * Enable this configuration.
	 */
	@XmlAttribute(name = "enabled")
	private Boolean enabled;

	/**
	 * Authorized applications for the AccessRequest.
	 */
	@XmlElement(name = "AuthorizedApplications")
	@Builder.Default
	private AuthorizedApplications authorizedApplications = new AuthorizedApplications();

	public boolean enabled() {
		return Boolean.TRUE.equals(enabled);
	}

	// duplicated values are merged with "|" as separator so far (used for logging only)
	public Map<String, String> getAllTriggerRoles() {
		var config = authorizedApplications.getAuthorizedApplicationList();
		if (config == null) {
			return Collections.emptyMap();
		}
		return config.stream().map(app -> Pair.of(app.getName(), app.getTriggerRole()))
					   .collect(Collectors.toMap(Pair::getKey, Pair::getValue, AccessRequest::mergeRoles));
	}

	private static String mergeRoles(String role1, String role2) {
		return role1 + "|" + role2;
	}
}
