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

package swiss.trustbroker.config.dto;

import java.util.List;
import java.util.Map;

import jakarta.xml.soap.SOAPConstants;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.config.RegexNameValue;

/**
 * Access request configuration.
 * <br>
 * Potentially breaking changes:
 * <ul>
 *     <li>With 1.10.0 value of attributes changed to Object to allow nested structures.</li>
 * </ul>
 *
 * @see swiss.trustbroker.api.accessrequest.service.AccessRequestService
 * @see swiss.trustbroker.federation.xmlconfig.AccessRequest
 * @see swiss.trustbroker.federation.xmlconfig.AuthorizedApplication
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AccessRequestConfig {

	/**
	 * Globally enable the feature.
	 */
	private boolean enabled;

	// INTERACTIVE
	// (interactive AR refers to a mode with user interaction, silent to one without)

	/**
	 * Global default for interactive Access Request service URL
 	 */
	private String interactiveServiceUrl;

	/**
	 * Global default for interactive Access Request service parameters.
	 */
	private String interactiveServiceParameters;

	/**
	 * Global default for interactive Access Request service parameters (multi tenant mode).
	 *
	 * @since 1.12.0
	 */
	private String interactiveMultiServiceParameters;

	/**
	 * Global default for optional request parameter added to URLs.
	 */
	private String centralCICD;

	/**
	 * Interactive Access Request result parameter name.
	 *
	 * @since 1.7.0
	 */
	private String interactiveResultParameter;

	/**
	 * Value of resultParameter indicating user has cancelled the process.
	 *
	 * @since 1.7.0
	 */
	private String interactiveResultUserCancel;

	// SILENT

	/**
	 * Global default for silent Access Request service URL
	 */
	private String silentServiceUrl;

	/**
	 * Global default for ID in requests sent by the AccessRequest.
	 */
	private String endpointReferenceAddress;

	/**
	 * Validity in seconds for WS-Trust expires.
	 */
	private int wsTrustRequestValiditySeconds;

	/**
	 * WS-Trust SOAP protocl.
	 * <br/>
	 * Default: SOAP 1.1 Protocol (alternative: SOAP 1.2 Protocol)
	 */
	@Builder.Default
	private String wsTrustSoapProtocolVersion = SOAPConstants.SOAP_1_1_PROTOCOL;

	/**
	 * Keystore for outbound requests.
	 */
	private KeystoreProperties truststore;

	/**
	 * Truststore for validating inbound messages.
	 */
	private KeystoreProperties signerTruststore;

	// Assertions

	/**
	 * Sign outgoing Access Request SAML messages (not re-using SecurityChecks.doSignSuccessResponse)
	 * Assertion signature is controlled by SecurityChecks.doSignAssertions for AccessRequest too.
	 * <br/>
	 * Default: true
 	 */
	@Builder.Default
	private boolean doSignSamlMessages = true;

	/**
	 * Access Request signature algorithm.
	 * <br/>
	 * Default: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
	 */
	@Builder.Default
	private String signatureMethodAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;

	/**
	 * Access Request canonicalization algorithm.
	 * <br/>
	 * Default: http://www.w3.org/2001/10/xml-exc-c14n#
	 */
	@Builder.Default
	private String canonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;

	/**
	 * Access requiest digest method.
	 * <br/>
	 * Default: null (Use default)
	 */
	@Builder.Default
	private String digestMethod = null;

	/**
	 * Signer for outbound messages.
	 */
	private KeystoreProperties signercert;

	/**
	 * Global default issuer ID.
	 */
	private String issuerId;

	/**
	 * Global default recipient ID.
	 */
	private String recipientId;

	/**
	 * Mappings that might be needed by the implementation.
 	 */
	private List<RegexNameValue> mappings;

	/**
	 * Custom attributes that might be needed by the implementation.
 	 */
	private Map<String, Object> attributes;

	/**
	 * Special attributes that might be marked as coming from the original issuer i.e. IDP
	 */
	private List<String> originalAttributes;

}
