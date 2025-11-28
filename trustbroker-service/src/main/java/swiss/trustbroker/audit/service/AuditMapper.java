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

package swiss.trustbroker.audit.service;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.LongConsumer;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections.CollectionUtils;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.springframework.http.HttpHeaders;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.audit.dto.OidcAuditData;
import swiss.trustbroker.common.saml.util.AttributeRegistry;
import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.tracing.TraceSupport;
import swiss.trustbroker.common.util.CollectionUtil;
import swiss.trustbroker.common.util.WebUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.homerealmdiscovery.util.DefinitionUtil;
import swiss.trustbroker.oidc.client.dto.AuthorizationCodeFlowRequest;
import swiss.trustbroker.saml.dto.ClaimSource;
import swiss.trustbroker.saml.dto.CpResponse;
import swiss.trustbroker.saml.util.ClaimSourceUtil;
import swiss.trustbroker.sessioncache.dto.AccessRequestSessionState;
import swiss.trustbroker.sessioncache.dto.Lifecycle;
import swiss.trustbroker.sessioncache.dto.SsoState;
import swiss.trustbroker.sessioncache.dto.StateData;
import swiss.trustbroker.util.WebSupport;

/**
 * Maps DTOs for auditing. Returns this to allow building from multiple sources. This class has a cyclic dependency to saml
 * package, but we live with that (clean on split if need be).
 * For auditing we can consume CPResponse attributes as follows:
 * <ul>
 * <li>AttributeName.name (from internal processing and IDM) can be directly consumed as name="value" (no deduplication)</li>
 * <li>AttributeName.fullyQualifiedName (from CP origin mostly) consumed as originName="value (fullyQualifiedName)"</li>
 * <li>If fullyQualifiedName cannot be mapped the part after the last slash is used lastPart="value (fullyQualifiedName)"</li>
 * </ul>
 * If we have colliding AttributeName.name when mapping back from AttributeName.fullyQualifiedName the winner in the map is OK.
 */
@Slf4j
public abstract class AuditMapper {

	public static final String HTTP_HEADER_X_FORWARDED_HOST = "X-Forwarded-Host"; // set by loadbalancer or other infra in front

	private final AuditDto.AuditDtoBuilder builder;

	private final Map<String, AuditDto.ResponseAttributeValues> responseAttributes;

	private final TrustBrokerProperties trustBrokerProperties;

	protected AuditMapper(TrustBrokerProperties trustBrokerProperties) {
		builder = AuditDto.builder();
		// we cannot add to a map with the builder -> collect entries separately and add the whole map in build()
		responseAttributes = new HashMap<>();
		this.trustBrokerProperties = trustBrokerProperties;
	}

	public AuditMapper mapFrom(CpResponse cpResponse) {
		if (cpResponse != null) {
			var ctxClasses = cpResponse.getContextClasses();
			// all data in here might be script manipulated
			setIfNotNull(builder::issuer, cpResponse.getIssuer());
			setIfNotNull(builder::applicationName, cpResponse.getApplicationName());
			setIfNotNull(builder::oidcClientId, cpResponse.getOidcClientId());
			setIfNotNull(builder::principal, cpResponse.getNameId());
			setIfNotNull(builder::cpNameId, cpResponse.getOriginalNameId());
			setIfNotNull(builder::mappedNameId, cpResponse.getMappedNameId());
			setIfNotNull(builder::destination, cpResponse.getDestination());
			setIfNotNull(builder::authLevel, cpResponse.getAuthLevel()); // config not helpful, we need the actual data...
			setIfNotNull(builder::ctxClasses, listToString(ctxClasses)); // ... here
			setIfNotNull(builder::eventType, EventType.RESPONSE);
			mapAttributes(cpResponse);
		}
		return this;
	}

	protected abstract AuditMapper mapAttributes(CpResponse cpResponse);

	protected abstract AuditMapper mapClaims(CpResponse cpResponse);

	public AuditMapper mapFrom(RequestAbstractType request) {
		if (request == null) {
			return this;
		}
		setIfNotNull(builder::conversationId, TraceSupport.switchToConversationFromSamlId(request.getID()));
		setIfNotNull(builder::messageId, request.getID());
		setIfNotNull(builder::issuer, request.getIssuer().getValue());
		setIfNotNull(builder::destination, request.getDestination());
		setIfNotNull(builder::samlMessage, request);
		if (request instanceof AuthnRequest authnRequest) {
			var ctxClasses = OpenSamlUtil.extractAuthnRequestContextClasses(authnRequest);
			setIfNotNull(builder::assertionConsumerUrl, authnRequest.getAssertionConsumerServiceURL());
			setIfNotNull(builder::ctxClasses, listToString(ctxClasses));
			setIfNotNull(builder::eventType, EventType.AUTHN_REQUEST);
		}
		else if (request instanceof LogoutRequest) {
			setIfNotNull(builder::eventType, EventType.LOGOUT_REQUEST);
		}
		else if (request instanceof ArtifactResolve) {
			setIfNotNull(builder::eventType, EventType.ARTIFACT_RESOLVE);
		}
		return this;
	}

	public AuditMapper mapFrom(AuthorizationCodeFlowRequest request) {
		if (request == null) {
			return this;
		}
		setIfNotNull(builder::oidcClientId, request.clientId());
		setIfNotNull(builder::destination, request.destination());
		setIfNotNull(builder::assertionConsumerUrl, request.assertionConsumerUrl());
		setIfNotNull(builder::ctxClasses, listToString(request.acrValues()));
		setIfNotNull(builder::scopes, listToString(request.scopes()));
		setIfNotNull(builder::eventType, EventType.AUTHN_REQUEST);

		return this;
	}

	public AuditMapper mapFrom(HttpServletRequest request) {
		if (request != null) {
			setIfNotNull(builder::clientType, WebSupport.getUserAgent(request));
			setIfNotNull(builder::clientNetwork, WebSupport.getClientNetwork(request, trustBrokerProperties.getNetwork()));
			setIfNotNull(builder::deviceId, WebSupport.getDeviceId(request));
			// entry detection
			var directHost = WebUtil.getHeader(HttpHeaders.HOST, request);
			var clientHost = WebUtil.getHeader(HTTP_HEADER_X_FORWARDED_HOST, request);
			setIfNotNull(builder::entryId, clientHost == null ? directHost : clientHost);
			setIfNotNull(builder::url, request.getRequestURL().toString());
			var httpReferer = extractReferrer(WebUtil.getReferer(request));
			setIfNotNull(builder::referrer, httpReferer);
		}
		return mapIps(WebUtil.getClientIp(request), WebUtil.getGatewayIp(request, true));
	}

	public AuditMapper mapFrom(StateData stateData) {
		if (stateData != null) {
			mapFrom(stateData.getCpResponse());
			mapFrom(stateData.getAccessRequest());
			mapFrom(stateData.getSsoState());
			mapFrom(stateData.getLifecycle());
			setIfNotNull(builder::assertionConsumerUrl, stateData.getAssertionConsumerServiceUrl());
			setIfNotNull(builder::sessId, stateData.getId());
			setIfNotNull(builder::deviceIdAccepted, stateData.getDeviceId());
			// issuer is from the message, rpIssuer and cpIssuer reflect the federation relation
			setIfNotNull(builder::rpIssuer, stateData.getRpIssuer());
			setIfNotNull(builder::cpIssuer, stateData.getCpIssuer());
			setIfNotNull(builder::conversationId, stateData.getLastConversationId()); // related to initiating auth request
			setIfNotNull(builder::ssoSessionId, stateData.getSsoSessionId());
			setIfNotNull(builder::applicationName, stateData.getRpApplicationName()); // AuthnRequest only
			setIfNotNull(builder::oidcClientId, stateData.getRpOidcClientId()); // AuthnRequest only
			setIfNotNull(builder::profileExtId, stateData.getSelectedProfileExtId()); // IDM
			// RP state referrer for OIDC is always same as message referrer
			if (stateData.getRpOidcClientId() == null) {
				var rpReferrer = extractReferrer(stateData.getRpReferer());
				setIfNotNull(builder::rpReferrer, rpReferrer);
			}
			mapLoginDuration(stateData);
		}
		return this;
	}

	private AuditMapper mapLoginDuration(StateData stateData) {
		if (stateData.getSpStateData() != null) {
			// use SP state data init time because of SSO
			setDurationSecs(builder::loginDurationSecs, stateData.getSpStateData().getLifecycle().getInitTime(),
					stateData.getLifecycle().getLastAuthTimestamp());
		}
		return this;
	}

	public AuditMapper mapFrom(SsoState ssoState) {
		if (ssoState != null) {
			setIfNotNull(builder::ssoGroupName, ssoState.getSsoGroupName());
			setIfNotNull(builder::ssoQoa, ssoState.getSsoQoa());
			builder.ssoParticipantCount(ssoState.getSsoParticipants().size());
		}
		return this;
	}

	public AuditMapper mapFrom(AccessRequestSessionState accessRequestSessionState) {
		if (accessRequestSessionState != null) {
			setIfNotNull(builder::arResponseId, accessRequestSessionState.getResponseId());
			if (accessRequestSessionState.getState() != null) {
				setIfNotNull(builder::arState, accessRequestSessionState.getState().name());
			}
			if (accessRequestSessionState.getMode() != null) {
				setIfNotNull(builder::arMode, accessRequestSessionState.getMode());
			}
			setIfNotNull(builder::arReturnUrl, accessRequestSessionState.getReturnUrl());
			setDurationSecs(builder::arDurationSecs, accessRequestSessionState.getSentTime(), accessRequestSessionState.getCompletedTime());
		}
		return this;
	}

	public AuditMapper mapFrom(Lifecycle lifecycle) {
		if (lifecycle != null) {
			setIfNotNull(builder::ssoEstablishedTime, lifecycle.getSsoEstablishedTime());
			setIfNotNull(builder::expirationTime, lifecycle.getExpirationTime());
		}
		return this;
	}

	public AuditMapper mapFrom(StatusResponseType response) {
		if (response == null) {
			return this;
		}
		if (response instanceof Response samlResponse) {
			mapResponse(samlResponse);
			setIfNotNull(builder::eventType, EventType.RESPONSE);
		}
		else if (response instanceof LogoutResponse) {
			setIfNotNull(builder::eventType, EventType.LOGOUT_RESPONSE);
		}
		else if (response instanceof ArtifactResponse) {
			setIfNotNull(builder::eventType, EventType.ARTIFACT_RESPONSE);
		}
		mapStatus(response);

		setIfNotNull(builder::messageId, response.getID());
		setIfNotNull(builder::issuer, response.getIssuer().getValue());
		setIfNotNull(builder::destination, response.getDestination());
		setIfNotNull(builder::samlMessage, response);
		return this;
	}

	public AuditMapper mapFrom(Assertion assertion) {
		if (assertion == null) {
			return this;
		}
		if (assertion.getID() != null) {
			setIfNotNull(builder::conversationId, assertion.getID()); // if ID is prefixed with S2-
		}
		if (assertion.getIssuer() != null) {
			setIfNotNull(builder::issuer, assertion.getIssuer().getValue());
		}
		if (assertion.getSubject() != null && assertion.getSubject().getNameID() != null) {
			setIfNotNull(builder::principal, assertion.getSubject().getNameID().getValue());
		}
		if (CollectionUtils.isNotEmpty(assertion.getAttributeStatements())) {
			assertion.getAttributeStatements().forEach(as ->
				as.getAttributes().forEach(this::mapFrom)
			);
		}
		setIfNotNull(builder::samlMessage, assertion);
		return this;
	}

	private void mapFrom(Attribute attribute) {
		var name = attribute.getName();
		var cid = isCid(name);
		var values = SamlUtil.getAttributeValues(attribute);
		if (values.size() == 1) {
			addResponseAttribute(name, null, values.get(0), AuditDto.AttributeSource.SAML_RESPONSE, null, cid); // single value
		}
		else {
			addResponseAttribute(name, null, values, AuditDto.AttributeSource.SAML_RESPONSE, null, cid); // list
		}
		// overwrite conversationId if attribute was set by caller as a claim
		if (CoreAttributeName.CONVERSATION_ID.equalsByNameOrNamespace(name)) {
			var conversationId = values.get(0);
			setIfNotNull(builder::conversationId, conversationId);
			TraceSupport.switchToConversation(conversationId);
		}
	}

	public AuditMapper mapFrom(OidcAuditData oidcAuditData) {
		if (oidcAuditData != null) {
			if (oidcAuditData.getOidcLogoutUrl() != null) {
				setIfNotNull(builder::eventType, EventType.OIDC_LOGOUT);
			}
			setIfNotNull(builder::oidcClientId, oidcAuditData.getOidcClientId());
			setIfNotNull(builder::ssoSessionId, oidcAuditData.getSsoSessionId());
			setIfNotNull(builder::destination, oidcAuditData.getOidcLogoutUrl());
			setIfNotNull(builder::conversationId, TraceSupport.getOwnTraceParent());
			return this;
		}
		return this;
	}

	public AuditMapper mapFromRstRequestAssertion(Assertion assertion) {
		setIfNotNull(builder::eventType, EventType.RST_REQUEST);
		return mapFrom(assertion);
	}

	public AuditMapper mapFromRstResponseAssertion(Assertion assertion) {
		setIfNotNull(builder::eventType, EventType.RST_RESPONSE);
		return mapFrom(assertion);
	}

	public AuditMapper mapFromThreadContext() {
		setIfNotNull(builder::traceId, TraceSupport.getCallerTraceParent());
		setIfNotNull(builder::conversationId, TraceSupport.getOwnTraceParent());
		return mapIps(TraceSupport.getClientIp(), TraceSupport.getGatewayIp());
	}

	private AuditMapper mapIps(String clientIp, String gatewayIp) {
		setIfNotNull(builder::clientIP, clientIp);
		if (clientIp == null || !clientIp.equals(gatewayIp)) {
			setIfNotNull(builder::gatewayIP, gatewayIp);
		}
		return this;
	}

	public AuditMapper mapFrom(RelyingParty relyingParty) {
		if (relyingParty != null) {
			setIfNotNull(builder::rpIssuer, relyingParty.getId());
			setIfNotNull(builder::clientName, relyingParty.getClientName());
			setIfNotNull(builder::billingId, relyingParty.getBillingId());
		}
		return this;
	}

	public AuditMapper mapFrom(ClaimsParty claimsParty) {
		if (claimsParty != null) {
			setIfNotNull(builder::cpIssuer, claimsParty.getId());
		}
		return this;
	}

	private void mapResponse(Response response) {
		if (CollectionUtils.isEmpty(response.getAssertions())) {
			return;
		}
		List<String> ctxClasses = new ArrayList<>();
		for (var assertion : response.getAssertions()) {
			var subject = assertion.getSubject();
			if (subject == null) {
				continue;
			}
			var nameId = subject.getNameID();
			if (nameId != null) {
				setIfNotNull(builder::principal, nameId.getValue());
			}
			for (var subjectConfirmation : subject.getSubjectConfirmations()) {
				nameId = subjectConfirmation.getNameID();
				if (nameId != null) {
					setIfNotNull(builder::principal, nameId.getValue());
				}
			}
			mapContextClasses(assertion, ctxClasses);
		}
	}

	private void mapContextClasses(Assertion assertion, List<String> ctxClasses) {
		List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
		for (AuthnStatement authnStatement : authnStatements) {
			var contextClass = OpenSamlUtil.extractAuthnStatementContextClass(authnStatement);
			if (contextClass != null) {
				ctxClasses.add(contextClass);
			}
		}
		setIfNotNull(builder::ctxClasses, listToString(ctxClasses));
	}

	private void mapStatus(StatusResponseType response) {
		var status = response.getStatus();
		if (status != null) {
			var statusCode = OpenSamlUtil.getStatusCode(response);
			var statusMessage = OpenSamlUtil.getStatusMessage(response);
			var nestedStatusCode = OpenSamlUtil.getNestedStatusCode(response);
			setIfNotNull(builder::status, statusCode);
			setIfNotNull(builder::statusMessage, statusMessage);
			setIfNotNull(builder::nestedStatus, nestedStatusCode);
		}
	}

	public <T> AuditMapper mapFromDefinitions(Map<Definition, T> definitions, AuditDto.AttributeSource source) {
		if (definitions != null) {
			definitions.forEach((key, value) -> {
				if (value != null) {
					var finalSource = mapSource(key.getSource(), source);
					addResponseAttribute(key.getName(), key.getNamespaceUri(), value, finalSource, key.getSource(), key.getCid());
				}
			});
		}
		return this;
	}

	// OIDC auditing
	public AuditMapper mapFromClaims(Map<String, Object> claims, AuditDto.AttributeSource source) {
		if (claims != null) {
			claims.forEach((key, value) -> {
				if (value != null) {
					var cid = isCid(key);
					addResponseAttribute(key, null, value, source, null, cid);
				}
			});
		}
		return this;
	}

	static AuditDto.AttributeSource mapSource(String querySource, AuditDto.AttributeSource source) {
		if (querySource != null) {
			if (querySource.equals(ClaimSource.CP.name())) {
				return source != null ? source : AuditDto.AttributeSource.CP_RESPONSE;
			}
			// we loose some details in case of multiple queries for now but the counter will show ambiguities
			return AuditDto.AttributeSource.IDM_RESPONSE;
		}
		return source;
	}

	private void addResponseAttribute(String name, String namespaceUri, Object value,
			AuditDto.AttributeSource source, String querySource, Boolean cid) {
		if (value == null || name == null) {
			return;
		}

		// eliminate brackets in output showing 'value' instead of '[value]'
		value = flattenList(value);

		// handle name being passed in as FQ and swap FQ- and short-name
		if (namespaceUri == null) {
			var truncatedName = DefinitionUtil.truncateNamespace(name);
			if (truncatedName != null) {
				namespaceUri = name;
				name = truncatedName;
			}
		}
		var finalQuerySource = querySource != null && querySource.contains(ClaimSourceUtil.SEPARATOR) ?
				querySource.split(ClaimSourceUtil.SEPARATOR)[1] : querySource;
		putResponseAttribute(name, namespaceUri, value, source, finalQuerySource, cid);
	}

	private static String listToString(List<String> ctxClasses) {
		return CollectionUtils.isNotEmpty(ctxClasses) ? CollectionUtil.toLogString(ctxClasses) : null;
	}

	private static Object flattenList(Object value) {
		if (value instanceof List<?> list) {
			value = list.size() == 1 ? list.get(0) : value;
		}
		return value;
	}

	private static Boolean isCid(String key) {
		var attributeName = AttributeRegistry.forName(key);
		return attributeName != null ? attributeName.getCid() : null;
	}

	// aggregate all values with same short name
	private void putResponseAttribute(String name, String namespaceUri, Object value,
			AuditDto.AttributeSource source, String querySource, Boolean cid) {
		var attributeValues = responseAttributes.computeIfAbsent(name, key -> new AuditDto.ResponseAttributeValues());
		var attributeValue = AuditDto.ResponseAttributeValue.of(value, namespaceUri, source, querySource, cid);
		if (!attributeValues.getValues().contains(attributeValue)) {
			attributeValues.getValues().add(attributeValue);
		}
	}

	private static <T> void setIfNotNull(Consumer<T> methodReference, T value) {
		if (value != null) {
			methodReference.accept(value);
		}
	}

	private static void setDurationSecs(LongConsumer methodReference, Timestamp start, Timestamp end) {
		if (end != null && start != null) {
			var secs = TimeUnit.MILLISECONDS.toSeconds(end.getTime() - start.getTime());
			// negative time would indicate a new period has started, but not yet completed (e.g. for SSO)
			if (secs >= 0) {
				methodReference.accept(secs);
			}
		}
	}

	// As this may be stored, query hurts usually and long URLs are not of interest anyway and might contain secret information.
	static String extractReferrer(String referrer) {
		if (referrer != null && referrer.length() > 8) {
			var initialLen = referrer.length();
			var maxLen = 66;
			// shorten (this could be enough actually)
			if (referrer.length() > maxLen) {
				referrer = referrer.substring(0, maxLen);
			}
			// discard query possible data
			var blackListedChars = new char[] { '?', ';', '%', '#' };
			for (char blackListedChar : blackListedChars) {
				var charPos = referrer.indexOf(blackListedChar);
				if (charPos > 0) {
					referrer = referrer.substring(0, charPos);
				}
			}
			// mark that we have dropped data
			if (initialLen > maxLen) {
				referrer += "...";
			}
		}
		return referrer;
	}

	public AuditDto build() {
		if (!responseAttributes.isEmpty()) {
			builder.responseAttributes(responseAttributes);
		}
		return builder.build();
	}

}
