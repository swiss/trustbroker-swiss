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
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import swiss.trustbroker.common.saml.dto.SamlBinding;

/**
 * Configuration for SAMl Artifact Binding.
 */
@XmlRootElement(name = "ArtifactBinding")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ArtifactBinding implements Serializable {

	/**
	 * Mode for inbound Artifact binding.
	 */
	@XmlAttribute(name = "inboundMode")
	private ArtifactBindingMode inboundMode;

	/**
	 * Mode for outbound Artifact binding.
	 */
	@XmlAttribute(name = "outboundMode")
	private ArtifactBindingMode outboundMode;

	/**
	 * Default expected sourceId is <pre>Hex(Sha1(ClaimsParty.id))</pre>.
	 * Allow overriding this with <pre>Hex(Sha1(sourceId))</pre>.
 	 */
	@XmlAttribute(name = "sourceId")
	private String sourceId;

	/**
	 * 	Overriding sourceId with encoded value directly in case it is not calculated in the expected way.
 	 */
	@XmlAttribute(name = "sourceIdEncoded")
	private String sourceIdEncoded;

	public boolean useArtifactBinding(SamlBinding requestBinding, SamlBinding requestedResponseBinding) {
		if (outboundMode == null) {
			return false;
		}
		return switch (outboundMode) {
			case REQUIRED -> true;
			case SUPPORTED -> requestedResponseBinding == SamlBinding.ARTIFACT ||
					(requestedResponseBinding == null && requestBinding == SamlBinding.ARTIFACT);
			case NOT_SUPPORTED -> false;
		};
	}

	public boolean validInboundBinding(SamlBinding actualBinding) {
		if (inboundMode == null) {
			return true;
		}
		return switch (inboundMode) {
			case REQUIRED -> actualBinding == SamlBinding.ARTIFACT;
			case SUPPORTED -> true;
			case NOT_SUPPORTED -> actualBinding != SamlBinding.ARTIFACT;
		};
	}

}
