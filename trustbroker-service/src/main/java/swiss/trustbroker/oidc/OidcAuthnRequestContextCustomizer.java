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

package swiss.trustbroker.oidc;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import com.google.common.collect.Sets;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.Scoping;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.common.util.StringUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.federation.xmlconfig.Qoa;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.service.QoaMappingService;
import swiss.trustbroker.mapping.util.QoaMappingUtil;
import swiss.trustbroker.oidc.opensaml5.OpenSaml5AuthenticationRequestResolver;
import swiss.trustbroker.oidc.session.OidcSessionSupport;
import swiss.trustbroker.util.HrdSupport;

@AllArgsConstructor
@Slf4j
class OidcAuthnRequestContextCustomizer implements Consumer<OpenSaml5AuthenticationRequestResolver.AuthnRequestContext> {

	private final TrustBrokerProperties properties;

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final QoaMappingService qoaMappingService;

	@Override
	public void accept(OpenSaml5AuthenticationRequestResolver.AuthnRequestContext authnRequestContext) {
		var authnRequest = authnRequestContext.getAuthnRequest();
		// Pass on client_id as applicationName too via SAML ProviderName
		authnRequest.setProviderName(OidcSessionSupport.getOidcClientId(authnRequestContext.getRequest(), relyingPartyDefinitions));
		// Pass OIDC sessionId as conversationId for E2E tracking
		authnRequest.setID(TraceSupport.getOwnTraceParentForSaml());
		// Handle prompt=login as forceAuthn=true
		if (OidcUtil.isOidcPromptLogin(authnRequestContext.getRequest())) {
			authnRequest.setForceAuthn(true);
		}
		// map HTTP acr_values or config Qoa settings to context classes
		var contextClasses = constructAuthnRequestContextClasses(authnRequestContext.getRequest());
		authnRequest.setRequestedAuthnContext(contextClasses);
		// if client sends a hrd_hint we propagate it (it's called scoping)
		authnRequest.setScoping(constructIdpScoping(authnRequestContext.getRequest()));
	}

	private RequestedAuthnContext constructAuthnRequestContextClasses(HttpServletRequest httpServletRequest) {
		// QoA/LoA mapping
		var acrValues = httpServletRequest.getParameter(OidcUtil.OIDC_ACR_VALUES);
		var clientId = OidcConfigurationUtil.getClientIdFromRequest(httpServletRequest);
		Set<String> qoas = new HashSet<>();
		if (acrValues != null) {
			qoas.addAll(OidcUtil.convertAcrToContextClasses(acrValues));
			log.debug("Got qoas={} from HTTP request {}={}", qoas, OidcUtil.OIDC_ACR_VALUES, StringUtil.clean(acrValues));
		}
		if (qoas.isEmpty()) {
			qoas = getQoaFromConfiguration(clientId, properties.getSecurity().isEnforceQoaIfMissing());
			log.debug("Got qoas={} from clientId={} configuration", qoas, clientId);
		}
		return SamlFactory.createRequestedAuthnContext(qoas, null);
	}

	private Scoping constructIdpScoping(HttpServletRequest httpServletRequest) {
		var hrdHint = HrdSupport.getHrdHintParameter(httpServletRequest, properties);
		if (hrdHint != null) {
			return OpenSamlUtil.constructIdpScoping(hrdHint);
		}
		return null;
	}

	private Qoa getQoaConfig(String clientId) {
		// from Oidc Client (if multiple clients differ in Qoa requirements)
		var oidcClient = relyingPartyDefinitions.getOidcClientConfigById(clientId, properties);
		if (oidcClient.isPresent() && oidcClient.get().getQoa() != null) {
			return oidcClient.get().getQoa();
		}
		// from RelyingParty
		var relyingParty = relyingPartyDefinitions.getRelyingPartyByOidcClientId(clientId, clientId, properties, false);
		if (relyingParty.getQoa() != null) {
			return relyingParty.getQoa();
		}
		return null;
	}

	private Set<String> getQoaFromConfiguration(String clientId, boolean enforceQoaIfMissing) {
		List<String> qoas = null;

		var qoaConfig = getQoaConfig(clientId);
		if (qoaConfig != null) {
			qoas = qoaMappingService.computeDefaultQoaFromConf(new QoaConfig(qoaConfig, clientId));
			log.debug("Set Context classes={} from Oidc.Client.Qoa for clientId={}", qoas, StringUtil.clean(clientId));
		}

		QoaMappingUtil.rejectRequestIfQoaConfMissing(qoaConfig, enforceQoaIfMissing, clientId);

		// global fallback
		if (qoas == null) {
			qoas = getDefaultQoa();
			if (log.isWarnEnabled()) {
				log.info("Missing acr_values in request, RelyingParty.Qoa and Oidc.Client.Qoa configuration for clientId={}."
						+ " Using global oidcDefaultQoa={}", StringUtil.clean(clientId), qoas);
			}
		}
		return Sets.newHashSet(qoas);
	}

	private List<String> getDefaultQoa() {
		var oidc = properties.getOidc();
		if (oidc.getDefaultQoa() != null) {
			return List.of(oidc.getDefaultQoa());
		}
		log.error("Missing Qoa default value from application.yml.");
		return new ArrayList<>();
	}

}
