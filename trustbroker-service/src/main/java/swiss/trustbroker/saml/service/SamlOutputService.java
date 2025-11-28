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

package swiss.trustbroker.saml.service;

import java.util.HashMap;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import net.shibboleth.shared.codec.HTMLEncoder;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.security.credential.Credential;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.api.saml.dto.EncodingParameters;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.exception.TrustBrokerException;
import swiss.trustbroker.common.saml.dto.ArtifactResolutionParameters;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.CustomHttpPostEncoder;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlTracer;
import swiss.trustbroker.common.saml.util.VelocityUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;

@Service
@AllArgsConstructor
public class SamlOutputService implements OutputService {

	private final TrustBrokerProperties trustBrokerProperties;

	private final ArtifactCacheService artifactCacheService;

	private final VelocityEngine velocityEngine;

	@Override
	public <T extends RequestAbstractType> void sendRequest(T request,
			Credential credential, String relayState, String endpoint,
			HttpServletResponse httpServletResponse, EncodingParameters encodingParameters,
			DestinationType destinationType) {
		var arParams = createArtifactResolutionParameters();
		OpenSamlUtil.sendSamlRequest(velocityEngine, artifactCacheService.getArtifactMap(),
				SamlBinding.of(encodingParameters.isUseArtifactBinding(), encodingParameters.isUseRedirectBinding()),
				arParams, request, httpServletResponse, credential, endpoint, relayState, destinationType.getAlias());
	}

	@Override
	public <T extends StatusResponseType> void sendResponse(T response,
			Credential credential, String requestRelayState, String endpoint,
			HttpServletResponse httpServletResponse, EncodingParameters encodingParameters,
			DestinationType destinationType) {
		var context = OpenSamlUtil.createMessageContext(response, credential, endpoint, requestRelayState);
		try {
			// send
			// request based conditions - checked first
			if (encodingParameters.isUseArtifactBinding()) {
				var arParams = createArtifactResolutionParameters();
				OpenSamlUtil.initAndEncodeSamlArtifactMessage(httpServletResponse, context, response.getIssuer().getValue(),
						velocityEngine, arParams, artifactCacheService.getArtifactMap());
			}
			else if (encodingParameters.isUseSoapBinding()) {
				OpenSamlUtil.encodeSamlSoapMessage(httpServletResponse, context);
			}
			// config based conditions - checked after
			else if (encodingParameters.isUseRedirectBinding()) {
				if (response instanceof LogoutResponse) {
					// LogoutResponse is using POST template for SLO notifications for REDIRECT binding
					encodeSamlRedirectMessageInTemplate(response, credential, requestRelayState, endpoint,
							httpServletResponse, encodingParameters);
				}
				else {
					OpenSamlUtil.encodeSamlRedirectMessage(httpServletResponse, context, null);
				}
			}
			else {
				HTTPPostEncoder encoder = null;
				if (response instanceof LogoutResponse) {
					encoder = new CustomHttpPostEncoder<>(VelocityUtil.VELOCITY_SLO_TEMPLATE_ID,
							encodingParameters.getTemplateParameters());
				}
				OpenSamlUtil.encodeSamlPostMessage(httpServletResponse, context, velocityEngine, encoder);
			}

			// trace
			SamlTracer.logSamlObject("<<<<< Send SAML Response to " + destinationType.getAlias(), response);
		}
		catch (TrustBrokerException ex) {
			throw ex;
		}
		catch (RuntimeException e) {
			throw new TechnicalException(String.format("Cannot send SAML response: %s", e.getMessage()), e);
		}
	}

	private <T extends StatusResponseType> void encodeSamlRedirectMessageInTemplate(T message, Credential credential,
			String requestRelayState, String endpoint, HttpServletResponse httpServletResponse,
			EncodingParameters encodingParameters) {
		// copy input parameters for modification:
		var parameters = new HashMap<>(encodingParameters.getTemplateParameters());
		parameters.computeIfAbsent(VelocityUtil.VELOCITY_PARAM_ACTION, key -> HTMLEncoder.encodeForHTMLAttribute(endpoint));
		parameters.putIfAbsent(SamlIoUtil.SAML_RELAY_STATE, requestRelayState);
		parameters.putIfAbsent(VelocityUtil.VELOCITY_PARAM_XTB_HTTP_METHOD, HttpMethod.GET.name());

		// message
		var encodedMessage = SamlIoUtil.encodeSamlRedirectData(message);
		var isRequest = message instanceof RequestAbstractType;
		parameters.put(isRequest ? SamlIoUtil.SAML_REQUEST_NAME : SamlIoUtil.SAML_RESPONSE_NAME, encodedMessage);

		// signature
		if (credential != null) {
			var signatureAlgorithm = SamlIoUtil.getSamlRedirectSignatureAlgorithmWithDefault(
					encodingParameters.getSignatureAlgorithm());
			var signature = SamlIoUtil.buildEncodedSamlRedirectSignature(message, credential, signatureAlgorithm,
					requestRelayState, encodedMessage);
			parameters.put(VelocityUtil.VELOCITY_PARAM_XTB_SIG_ALG, WebUtil.urlEncodeValue(signatureAlgorithm));
			parameters.put(VelocityUtil.VELOCITY_PARAM_XTB_SIGNATURE, signature);
		}

		// output
		VelocityUtil.renderTemplate(velocityEngine, httpServletResponse, VelocityUtil.VELOCITY_SLO_TEMPLATE_ID, parameters);
	}

	private ArtifactResolutionParameters createArtifactResolutionParameters() {
		return ArtifactResolutionParameters.of(
				trustBrokerProperties.getSaml().getArtifactResolution().getServiceUrl(),
				trustBrokerProperties.getSaml().getArtifactResolution().getIndex(),
				trustBrokerProperties.getIssuer()
		);
	}

}
