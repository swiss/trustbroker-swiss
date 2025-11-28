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

import jakarta.xml.bind.annotation.XmlTransient;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;

/**
 * Keystore/truststore configuration.
 *
 * @since 1.10.0
 * @see Certificates
 */
@Data
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public abstract class SignerStore implements Serializable {

	private transient String resolvedCertPath;

	private transient String resolvedKeyPath;

	// XmlTransient not allowed on transient field (the Javadoc does not say transient is considered XmlTransient)
	@XmlTransient
	public String getResolvedCertPath() {
		return resolvedCertPath;
	}

	@XmlTransient
	public String getResolvedKeyPath() { return resolvedKeyPath; }

	/**
	 * Path of the certificate.
	 */
	public abstract String getCertPath();

	/**
	 * Path of the key.
	 */
	public abstract String getKeyPath();

	/**
	 * If the store contains multiple objects and a specific one shall be used.
	 */
	public abstract String getAlias();

	/**
	 * If the store format cannot be derived from the file extension.
	 */
	public abstract String getCertType();

	/**
	 * Password for the store.
	 */
	public abstract String getPassword();
}
