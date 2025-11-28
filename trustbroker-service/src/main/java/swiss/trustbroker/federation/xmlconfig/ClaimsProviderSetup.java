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
import java.util.ArrayList;
import java.util.List;

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Defines claims parties (CPs). Usually one per file for separation of concerns.
 */
@XmlRootElement(name = "ClaimsProviderSetup")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClaimsProviderSetup implements PathReference, Serializable {

	/**
	 * List of CPs.
	 */
	@XmlElement(name = "ClaimsParty")
	@Builder.Default
	private List<ClaimsParty> claimsParties = new ArrayList<>();

	private transient String subPath;

	private transient List<ClaimsParty> unfilteredClaimsParties;

	// XmlTransient not allowed on transient field (the Javadoc does not say transient is considered XmlTransient)

	@XmlTransient
	public List<ClaimsParty> getUnfilteredClaimsParties() {
		return unfilteredClaimsParties == null ? claimsParties : unfilteredClaimsParties;
	}

	@XmlTransient
	@Override
	public String getSubPath() { return subPath; }

	@Override
	public void setSubPath(String subPath) {
		this.subPath = subPath;
		// propagate
		if (claimsParties != null) {
			claimsParties.forEach(party -> party.setSubPath(subPath));
		}
	}

}
