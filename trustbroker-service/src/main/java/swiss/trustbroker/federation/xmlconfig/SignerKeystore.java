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
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

/**
 * Keystore configuration.
 *
 * @see Certificates
 */
@XmlRootElement(name = "SignerKeystore")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@EqualsAndHashCode(callSuper=true)
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class SignerKeystore extends SignerStore implements Serializable {

	/**
	 * Path of the certificate.
	 */
	@XmlElement(name = "CertPath", required = true)
	private String certPath;

	/**
	 * Path of the key.
	 */
	@XmlElement(name = "KeyPath")
	private String keyPath;

	/**
	 * If the store contains multiple objects and a specific one shall be used.
	 */
	@XmlElement(name = "Alias")
	private String alias;

	/**
	 * If the store format cannot be derived from the file extension.
	 */
	@XmlElement(name = "CertType")
	private String certType;

	/**
	 * Password for the store.
	 */
	@XmlElement(name = "Password", required = true)
	private String password;

}
