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
import swiss.trustbroker.common.saml.dto.SignatureParameters;

/**
 * Cryptographic setup of SAML signing as supported by Apache XML-security configuration.
 * In context of XTB the usual items used are:
 * <ul>
 *     <li>http://www.w3.org/2001/10/xml-exc-c14n# (canonicalization)</li>
 *     <li>http://www.w3.org/2000/09/xmldsig#rsa-sha1 (signature legacy)</li>
 *     <li>http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 (signature recommended)</li>
 *     <li>http://www.w3.org/2001/04/xmlenc#sha256 (digest)</li>
 * </ul>
 */
@XmlRootElement(name = "Signature")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Signature implements Serializable {

	/**
	 * Canonicalization algorithm.
	 */
	@XmlElement(name = "CanonicalizationAlgorithm")
	private String canonicalizationAlgorithm;

	/**
	 * Signature algorithm.
	 */
	@XmlElement(name = "SignatureMethodAlgorithm")
	private String signatureMethodAlgorithm;

	/**
	 * Digest algorithm.
	 */
	@XmlElement(name = "DigestMethod")
	private String digestMethod;

	public SignatureParameters.SignatureParametersBuilder getSignatureParametersBuilder() {
		return SignatureParameters.builder()
				.signatureAlgorithm(signatureMethodAlgorithm)
				.canonicalizationAlgorithm(canonicalizationAlgorithm)
				.digestMethod(digestMethod);
	}
}
