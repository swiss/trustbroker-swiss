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
import lombok.extern.slf4j.Slf4j;


/**
 * The certificate configurations contain file paths relative to <pre>${TRUSTBOKER_HOME}/keystore</pre>.
 * Files can contain a certificate for trust checks and
 * optionally a private key required for signing. The following formats are supported and the files should have this
 * as extensions:
 * <ul>
 *     <li>pem: OpenSSL compatible text representation</li>
 *     <li>p12: PKCS12 keystore format</li>
 *     <li>jks: Java specific keystore format (not recommended)</li>
 * </ul>
 * <br/>
 * Always specify <pre>$PKI_PASSPHRASE</pre> for passwords as a place-holder for the key decryption passphrase to be passed to the running
 * XTB process.
 */
@XmlRootElement(name = "Certificates")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class Certificates implements Serializable {

	/**
	 * Keystore for signing.
	 */
	@XmlElement(name = "SignerKeystore")
	private SignerKeystore signerKeystore;

	/**
	 * Truststore for signature verification.
	 */
	@XmlElement(name = "SignerTruststore")
	private SignerTruststore signerTruststore;

	/**
	 * Keystore for encryption.
	 */
	@XmlElement(name = "EncryptionKeystore")
	private SignerKeystore encryptionKeystore;

	/**
	 * Truststore for encryption verification.
	 */
	@XmlElement(name = "EncryptionTruststore")
	private SignerTruststore encryptionTruststore;

	/**
	 * Keystore for backend connections (via SAML the artifact resolution or OIDC metadata protocol).
	 *
	 * @since 1.9.0
	 */
	@XmlElement(name = "BackendKeystore")
	private SignerKeystore backendKeystore;

	/**
	 * Truststore for backend connections (via SAML the artifact resolution or OIDC metadata protocol).
	 *
	 * @since 1.9.0
	 */
	@XmlElement(name = "BackendTruststore")
	private SignerTruststore backendTruststore;

	/**
	 * @deprecated Use backendKeystore
	 */
	@Deprecated(since = "1.9.0", forRemoval = true)
	@XmlElement(name = "ArtifactResolutionKeystore")
	private SignerKeystore artifactResolutionKeystore;

	/**
	 * @deprecated Use backendTruststore
	 */
	@Deprecated(since = "1.9.0", forRemoval = true)
	@XmlElement(name = "ArtifactResolutionTruststore")
	private SignerTruststore artifactResolutionTruststore;

	public SignerKeystore getBackendKeystore() {
		// fallback for transition
		if (artifactResolutionKeystore != null) {
			return artifactResolutionKeystore;
		}
		return backendKeystore;
	}

	public SignerTruststore getBackendTruststore() {
		// fallback for transition
		if (artifactResolutionTruststore != null) {
			return artifactResolutionTruststore;
		}
		return backendTruststore;
	}
}
