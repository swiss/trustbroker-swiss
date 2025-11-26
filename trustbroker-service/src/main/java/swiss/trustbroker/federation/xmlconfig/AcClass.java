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

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlValue;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Authentication Context Class (ACClass).
 *
 * @since 1.9.0
 */
@XmlRootElement(name = "ACClass")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AcClass implements Serializable {

	/**
	 * ACClass QoA order.
	 */
	@XmlAttribute(name = "order")
	private Integer order;

	/**
	 * Enable mapping of inbound QoA.
	 * <br/>
	 * Default: true, set to false in order to disambiguate mappings.
	 */
	@XmlAttribute(name = "mapInbound")
	@Builder.Default
	private Boolean mapInbound = Boolean.TRUE;

	/**
	 * Enable mapping of outbound QoA.
	 * <br/>
	 * Default: true, set to false in order to disambiguate mappings.
	 */
	@XmlAttribute(name = "mapOutbound")
	@Builder.Default
	private Boolean mapOutbound = Boolean.TRUE;

	/**
	 * Replace inbound Qoa from RP request. Only works with Qoa.replaceInbound together
	 * <br/>
	 * Default: true
	 *
	 * @since 1.10.0
	 */
	@XmlAttribute(name = "replaceInbound")
	@Builder.Default
	private Boolean replaceInbound = Boolean.TRUE;

	/**
	 * If this Qoa is returned by the CP, but was not requested by the RP, downgrade it to the maximum Qoa requested by the RP.
	 * <br/>
	 * Default: false
	 */
	@XmlAttribute(name = "downgradeToMaximumRequested")
	@Builder.Default
	private Boolean downgradeToMaximumRequested = Boolean.FALSE;

	/**
	 * ACClass name
	 */
	@XmlValue
	private String contextClass;

	/**
	 * @param outbound true for outbound, false for inbound, null for both
	 * @return true if this mapping is to be applied
	 */
	public boolean applyForDirection(Boolean outbound) {
		return (outbound == null)
				|| (outbound && Boolean.TRUE.equals(mapOutbound))
				|| (!outbound && Boolean.TRUE.equals(mapInbound));

	}
}
