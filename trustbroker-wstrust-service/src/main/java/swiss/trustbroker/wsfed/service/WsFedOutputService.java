/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

package swiss.trustbroker.wsfed.service;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.shared.codec.HTMLEncoder;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.security.credential.Credential;
import org.opensaml.soap.wstrust.RequestSecurityTokenResponse;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import swiss.trustbroker.api.saml.dto.DestinationType;
import swiss.trustbroker.api.saml.dto.EncodingParameters;
import swiss.trustbroker.api.saml.service.OutputService;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.saml.util.VelocityUtil;
import swiss.trustbroker.wsfed.dto.WsFedAction;
import swiss.trustbroker.wstrust.util.WsTrustUtil;

@Service
@AllArgsConstructor
@Slf4j
public class WsFedOutputService implements OutputService {

	private final VelocityEngine velocityEngine;

	@Override
	public boolean applies(EncodingParameters encodingParameters) {
		return encodingParameters.isUseWsFedBinding();
	}

	@Override
	public <T extends RequestAbstractType> void sendRequest(T request,
			Credential credential, String relayState, String endpoint,
			HttpServletResponse httpServletResponse, EncodingParameters encodingParameters,
			DestinationType destinationType) {
		throw new TechnicalException("WsFedOutputService does not support requests");
	}

	@Override
	public <T extends StatusResponseType> void sendResponse(T response,
			Credential credential, String requestRelayState, String endpoint,
			HttpServletResponse httpServletResponse, EncodingParameters encodingParameters,
			DestinationType destinationType) {
		if (response instanceof LogoutResponse logoutResponse) {
			// LATER: support SSO notifications (pass through reply URL and use SLO Velocity template)
			log.debug("LogoutResponse to destination='{}' ignored for WS-Fed - handled by controller",
					logoutResponse.getDestination());
		}
		else if (response instanceof Response samlResponse) {
			processResponse(requestRelayState, httpServletResponse, samlResponse);
		}
		else {
			throw new TechnicalException(String.format("WsFedOutputService does not support response=%s",
					response.getClass().getName()));
		}
	}

	private void processResponse(String requestRelayState, HttpServletResponse httpServletResponse, Response samlResponse) {
		if (samlResponse.getDestination() == null) {
			throw new TechnicalException("Response contains no Destination");
		}
		if (CollectionUtils.isEmpty(samlResponse.getAssertions())) {
			throw new TechnicalException("Response contains no Assertions");
		}
		var requestSecurityTokenResponse = createSecurityTokenResponse(samlResponse);
		// The WS-FED action leading to a Response must be a sign in:
		encodeResponse(httpServletResponse, samlResponse.getDestination(), requestRelayState, requestSecurityTokenResponse,
				WsFedAction.ACTION_SIGN_IN.getAction());
	}

	// LATER: sign RSTR? In that case maybe move this up to the caller where the SAML Response is signed.
	private RequestSecurityTokenResponse createSecurityTokenResponse(Response samlResponse) {
		var assertion = samlResponse.getAssertions().get(0);
		var audienceUrls = SamlUtil.getAudiences(assertion);

		// note: using wstrust XML objects, not wsfed as AppliesTo of both packages has the same QName
		// and thus marshaling clashes - WS-Trust namespace of RequestSecurityTokenResponse differs:
		// http://docs.oasis-open.org/ws-sx/ws-trust/200512 vs. http://schemas.xmlsoap.org/ws/2005/02/trust
		assertion.setParent(null); // detach from Response before re-adding to RSTR
		var rst = WsTrustUtil.createRequestedSecurityToken(assertion);
		var rstResponse = WsTrustUtil.createSecurityTokenResponse(rst);
		if (!audienceUrls.isEmpty()) {
			var appliesTo = WsTrustUtil.createResponseAppliesTo(audienceUrls.get(0));
			rstResponse.getUnknownXMLObjects().add(appliesTo);
		}
		return rstResponse;
	}

	private void encodeResponse(HttpServletResponse httpServletResponse, String destination,
			String requestRelayState, RequestSecurityTokenResponse requestSecurityTokenResponse, String action) {
		var result = SamlIoUtil.marshalXmlObjectToString(requestSecurityTokenResponse);
		var resultEncoded = HTMLEncoder.encodeForHTMLAttribute(result);
		Map<String, String> contextValues = new HashMap<>();
		contextValues.put(VelocityUtil.VELOCITY_PARAM_XTB_ACTION, action);
		contextValues.put(VelocityUtil.VELOCITY_PARAM_XTB_CONTEXT, requestRelayState);
		contextValues.put(VelocityUtil.VELOCITY_PARAM_XTB_RESULT, resultEncoded);
		contextValues.put(VelocityUtil.VELOCITY_PARAM_ACTION, destination);
		VelocityUtil.renderTemplate(velocityEngine, httpServletResponse, VelocityUtil.VELOCITY_WS_FED_TEMPLATE_ID, contextValues);
	}
}
