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

package swiss.trustbroker.oidc.tx;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.RelyingPartyDefinitions;
import swiss.trustbroker.oidc.OidcExceptionHelper;
import swiss.trustbroker.oidc.OidcFrameAncestorHandler;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.util.HeaderBuilder;
import swiss.trustbroker.util.HrdSupport;

@Slf4j
public class OidcTxResponseWrapper extends HttpServletResponseWrapper {

	private final RelyingPartyDefinitions relyingPartyDefinitions;

	private final HttpServletRequest request;

	private final TrustBrokerProperties trustBrokerProperties;

	private final ApiSupport apiSupport;

	private InMemoryServletOutputStream output = null;

	private final OidcFrameAncestorHandler frameAncestorHandler;

	private final HeaderBuilder headerBuilder;

	public OidcTxResponseWrapper(HttpServletRequest httpRequest, HttpServletResponse originResponse,
			RelyingPartyDefinitions relyingPartyDefinitions,
			TrustBrokerProperties trustBrokerProperties,
			ApiSupport apiSupport,
			OidcFrameAncestorHandler oidcFrameAncestorHandler) {
		super(originResponse);
		this.relyingPartyDefinitions = relyingPartyDefinitions;
		this.request = httpRequest;
		this.trustBrokerProperties = trustBrokerProperties;
		this.apiSupport = apiSupport;
		this.frameAncestorHandler = oidcFrameAncestorHandler;
		this.headerBuilder = HeaderBuilder.of(request, this, trustBrokerProperties, frameAncestorHandler);
	}

	public void catchOutputStream() {
		output = new InMemoryServletOutputStream();
	}

	public byte[] getBody() {
		return output.getData();
	}

	public void patchOutputStream(byte[] body) throws IOException {
		output = null;
		getOutputStream().write(body);
	}

	@Override
	public void setHeader(String name, String value) {
		value = fixValue(name, value);
		if (value != null) {
			super.setHeader(name, value);
		}
	}

	@Override
	public void addHeader(String name, String value) {
		value = fixValue(name, value);
		if (value != null) {
			super.addHeader(name, value);
		}
	}

	private String fixValue(String name, String value) {
		// Override any spring-sec magic allowing access to ourselves (spring per defaults sets DENY in code)
		if (name.equals(XFrameOptionsHeaderWriter.XFRAME_OPTIONS_HEADER)) {
			// no frame-options if we already set frame-ancestors
			if (frameAncestorHandler.hasAppliedFrameAncestors()) {
				value = null;
			}
			else if (XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name().equals(value)) {
				value = XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN.name();
			}
		}
		return value;
	}

	@Override
	public ServletOutputStream getOutputStream() throws IOException {
		if (output != null) {
			return output;
		}
		return super.getOutputStream();
	}

	@Override
	public void sendRedirect(String location) throws IOException {
		// should not happen so let the web container do whatever it does (ignoring as well)
		if (location == null) {
			super.sendRedirect(location);
			return;
		}

		// error forwarding to XTB error screen
		if (!OidcExceptionHelper.hasAuthenticationException(request) && OidcExceptionHelper.isSpringErrorPage(location)) {
			var oidcLocation = OidcExceptionHelper.buildLocationForAuthenticationException(
					request, location, trustBrokerProperties.getOidc().getIssuer(), "servlet-filter", apiSupport::isInternalUrl);
			if (oidcLocation != null) {
				log.debug("servlet redirect URL location={} mapped to oidcLocation={}", location, oidcLocation);
				location = oidcLocation;
			}
		}

		// actual OIDC manipulations
		else {
			var responseMode = request.getParameter(FragmentUtil.OIDC_RESPONSE_MODE);
			// fragment handling on ?code=X redirects (as spring-security ignores it)
			location = FragmentUtil.checkAndFixRedirectUri(location, request.getSession(false), responseMode);

			// ACR handling
			if (location.contains(ApiSupport.SPRING_SAML_AUTHENTICATE_CTXPATH)) {
				location = addAuthenticationContextParams(location);
			}

			// Keycloak realm compatibility (turned off per default)
			if (trustBrokerProperties.getOidc().isKeycloakTransparencyModeOn()) {
				location = OidcTxUtil.checkAndAddRealmContextPath(location, relyingPartyDefinitions, trustBrokerProperties);
			}
		}

		super.sendRedirect(location);
	}

	// handle acr on top of spring-security
	private String addAuthenticationContextParams(String location) {
		var ret = location;
		var requestURI = request.getRequestURI();
		if (requestURI.endsWith(ApiSupport.SPRING_OAUTH2_AUTHORIZE_CTXPATH)) {
			var clientId = request.getParameter(OidcUtil.OIDC_CLIENT_ID);
			var acrValues = request.getParameter(OidcUtil.OIDC_ACR_VALUES);
			var promptLogin = request.getParameter(OidcUtil.OIDC_PROMPT);
			var hrdHint = HrdSupport.getHrdHintParameter(request, trustBrokerProperties);
			var uriComponentsBuilder = UriComponentsBuilder.fromUriString(location);
			if (acrValues != null) {
				uriComponentsBuilder.queryParam(OidcUtil.OIDC_ACR_VALUES, UriUtils.encode(acrValues, StandardCharsets.UTF_8));
			}
			if (clientId != null) {
				uriComponentsBuilder.queryParam(OidcUtil.OIDC_CLIENT_ID, UriUtils.encode(clientId, StandardCharsets.UTF_8));
			}
			if (promptLogin != null) {
				uriComponentsBuilder.queryParam(OidcUtil.OIDC_PROMPT, UriUtils.encode(promptLogin, StandardCharsets.UTF_8));
			}
			if (hrdHint != null) {
				uriComponentsBuilder.queryParam(trustBrokerProperties.getHrdHintParameter(), UriUtils.encode(hrdHint, StandardCharsets.UTF_8));
			}
			ret = uriComponentsBuilder.build().toUriString();
		}
		log.debug("Constructed redirectUrl='{}' with parameters from request context", ret);
		return ret;
	}

	public HeaderBuilder headerBuilder() {
		return headerBuilder;
	}
}
