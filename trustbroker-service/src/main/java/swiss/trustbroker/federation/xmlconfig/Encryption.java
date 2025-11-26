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
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * This class describes the configuration of the SAML encryption for an RP.
 */
@XmlRootElement(name = "Encryption")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Encryption implements Serializable {

	/**
	 * Data encryption algorithm.
	 * <br/>
	 * Default: http://www.w3.org/2001/04/xmlenc#aes256-cbc
	 */
	@XmlElement(name = "DataEncryptionAlgorithm")
	private String dataEncryptionAlgorithm;

	/**
	 * Key encryption algorithm.
	 * <br/>
	 * Default: http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
	 */
	@XmlElement(name = "KeyEncryptionAlgorithm")
	private String keyEncryptionAlgorithm;

	/**
	 * Key placement (PEER, INLINE).
	 * <br/>
	 * Default: PEER
	 */
	@XmlElement(name = "KeyPlacement")
	@Builder.Default
	private EncryptionKeyPlacement keyPlacement = EncryptionKeyPlacement.PEER;

	/**
	 * Value emitted in Key Info (CERTIFICATE, SKI).
	 * <br/>
	 * Default: CERTIFICATE
	 * @since 1.10.0
	 */
	@XmlElement(name = "KeyInfo")
	@Builder.Default
	private EncryptionKeyInfo keyInfo = EncryptionKeyInfo.CERTIFICATE;
}
