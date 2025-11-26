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

package swiss.trustbroker.sessioncache.dto;

import java.io.Serializable;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import swiss.trustbroker.api.sessioncache.dto.SessionState;
import swiss.trustbroker.common.saml.dto.SamlBinding;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.saml.dto.CpResponse;

@Data
@Builder(toBuilder=true)
@AllArgsConstructor
@NoArgsConstructor
@RequiredArgsConstructor
@ToString
public class StateData implements Serializable, SessionState {

	@Id
	@NonNull
	private String id;

	@NonNull
	@Builder.Default
	private Lifecycle lifecycle = new Lifecycle();

	private String lastConversationId; // own conversation, OpenTelemetry compliant

	private String issuer;

	private String relayState;

	private StateData spStateData; // RP state that initiated this CP state

	private String issueInstant;

	private String referer;

	private String applicationName; // AuthnRequest.ProviderName to handle RP-ID ambiguities

	private List<String> contextClasses;

	private QoaComparison comparisonType;

	private String assertionConsumerServiceUrl;

	private CpResponse cpResponse;

	private String deviceId;

	private Boolean forceAuthn;

	// AuthnRequest was signed with a validated signature
	private Boolean signedAuthnRequest;

	private List<String> completedAuthnRequests;

	private String selectedProfileExtId;

	private String subjectNameId;

	// SAML session identification (always 0 in our case, correlates with ssoSessionId
	private String sessionIndex;

	private SamlBinding requestBinding;

	private SamlBinding requestedResponseBinding; // AuthnRequest.ProtocolBinding

	// external context tracking only so we do not have to expose out own ID
	private String ssoSessionId;

	private SsoState ssoState;

	private String oidcClientId;

	private String oidcSessionId; // 2nd key: Track code and sid of access_token, id_token claim

	private String oidcRefreshToken; // 3d key: opaque refresh_token when on /token endpoint clients want a new one

	private String oidcSessionData; // OIDC sub-system web session tracking on OIDC side sessions only

	private String oidcTokenData; // OIDC sub-system token tracking (OAuth2Authorization)

	private int oidcTokenCount;

	private String oidcNonce; // client side nonce

	private AccessRequestSessionState accessRequest;

	private String hrdHint;

	private Timestamp expirationTimestamp; // lifetime as seen by reaper

	@Builder.Default
	private Map<String, String> rpContext = new HashMap<>();

	// derived attribute getters
	// WARN: Session save requires these to be ignored and 'getDerived()' should never refer to 'derived'

	@JsonIgnore
	public String getRpIssuer() {
		return (spStateData != null) ? spStateData.getIssuer() : issuer;
	}

	@JsonIgnore
	public String getRpReferer() {
		return (spStateData != null) ? spStateData.referer : referer;
	}

	@JsonIgnore
	public String getRpApplicationName() {
		return (spStateData != null) ? spStateData.applicationName : applicationName;
	}

	@JsonIgnore
	public String getRpRelayState() {
		return (spStateData != null) ? spStateData.relayState : relayState;
	}

	@JsonIgnore
	public String getRpOidcClientId() {
		return (spStateData != null) ? spStateData.oidcClientId : oidcClientId;
	}

	@JsonIgnore
	public List<String> getRpContextClasses() {
		return (spStateData != null) ? spStateData.contextClasses : contextClasses;
	}

	@JsonIgnore
	public String getRpHrdHint() {
		return (spStateData != null) ? spStateData.hrdHint : hrdHint;
	}

	@JsonIgnore
	public String getCpIssuer() {
		return issuer;
	}

	@JsonIgnore
	public boolean isValid() {
		return lifecycle.isValid();
	}

	@JsonIgnore
	public boolean isExpired() {
		return lifecycle.isExpired();
	}

	public void reInit() {
		lifecycle.setLifecycleState(LifecycleState.INIT);
		if (spStateData != null) {
			spStateData.reInit();
		}
	}

	@JsonIgnore
	public boolean isOverdueAt(Instant deadline) {
		return lifecycle.isOverdueAt(Timestamp.from(deadline));
	}

	@JsonIgnore
	public boolean isSsoEstablished() {
		return lifecycle.isSsoEstablished() && hasSsoState();
	}

	@JsonIgnore
	public boolean isNotOidcSession() {
		return oidcSessionData == null;
	}

	@JsonIgnore
	public boolean hasSsoState() {
		return ssoState != null;
	}

	public SsoState initializedSsoState() {
		if (!hasSsoState()) {
			ssoState = new SsoState();
		}
		return ssoState;
	}

	@JsonIgnore
	public void addCompletedAuthnRequest(String authReqId) {
		if (completedAuthnRequests == null) {
			completedAuthnRequests = new ArrayList<>();
		}
		completedAuthnRequests.add(authReqId);
	}

	public void addSsoParticipant(SsoSessionParticipant ssoSessionParticipant) {
		initializedSsoState().getSsoParticipants().add(ssoSessionParticipant);
	}

	@JsonIgnore
	public boolean hasAccessRequest() {
		return accessRequest != null;
	}

	public AccessRequestSessionState initializedAccessRequest() {
		if (!hasAccessRequest()) {
			accessRequest = new AccessRequestSessionState();
		}
		return accessRequest;
	}

	@JsonIgnore
	public boolean forceAuthn() {
		return Boolean.TRUE.equals(forceAuthn);
	}

	@JsonIgnore
	public boolean isAuthnRequestSigned() {
		return Boolean.TRUE.equals(signedAuthnRequest);
	}

	/**
	 * @return null if SSO is not established
	 */
	public Instant getLatestSsoSessionEndTime(int defaultSsoSessionLifetimeSec) {
		if (!isSsoEstablished()) {
			return null;
		}
		var maxSessionTimeSec = ssoState.getMaxSessionTimeSecs();
		if (maxSessionTimeSec == 0) {
			maxSessionTimeSec = defaultSsoSessionLifetimeSec;
		}
		return getLifecycle().getSsoEstablishedTime().toInstant().plusSeconds(maxSessionTimeSec);
	}

}
