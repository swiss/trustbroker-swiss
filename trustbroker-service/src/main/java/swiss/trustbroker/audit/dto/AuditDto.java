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

package swiss.trustbroker.audit.dto;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import org.opensaml.core.xml.XMLObject;

/**
 * Represents the data that we can base reports on.
 */
@Data
@Builder
public class AuditDto {

	@AllArgsConstructor(access = AccessLevel.PACKAGE)
	@Getter
	public enum AttributeSource {
		SAML_RESPONSE("r"), // SAML response
		CP_RESPONSE("c"), // CP response filtered
		IDM_RESPONSE("i"), // IDM query results
		SCRIPT("s"), // Script manipulations
		DROPPED_RESPONSE("x"), // CP response dropped
		OIDC_RESPONSE(null); // no tagging

		private final String shortName;
	}

	// wrapped list do allow straight-forward distinction from List<> values
	@Data
	public static class ResponseAttributeValues {

		private final List<ResponseAttributeValue> values = new ArrayList<>();

		public static ResponseAttributeValues of(ResponseAttributeValue... attributeValues) {
			var result = new ResponseAttributeValues();
			for (var attributeValue : attributeValues) {
				result.values.add(attributeValue);
			}
			return result;
		}
	}

	@Data
	@Builder
	@AllArgsConstructor(staticName = "of")
	public static class ResponseAttributeValue {

		private Object value;

		private String namespaceUri;

		private AttributeSource source;

		private String querySource;

		private Boolean cid;

		public boolean hasSourceTag() {
			// there should be no querySource without source
			return (source != null && source.getShortName() != null) || (querySource != null);
		}
	}

	// name for eventType
	public static final String EVENT_NAME = "event";

	// name for samlMessage
	public static final String DETAIL_NAME = "detail";

	// name to configure responseAttributes (default for all, add '.name' for individual attributes)
	// note: just responseAttributes controls the whole list and overrides the above defaults and Definition.cid if true
	public static final String RESPONSE_ATTRIBUTES_NAME = "responseAttributesDefault";

	// RAW data and message identification

	@CustomLogging
	private EventType eventType; // maps to 'event'

	private String side; // rp or cp

	private String status; // response only

	private String statusMessage; // response only

	private String nestedStatus; // response only

	// SAML user attributes

	private String principal; // from response Subject NameID usually

	private String cpNameId; // incoming CP side principal

	private String mappedNameId; // CP side principal after subject mappings

	// HTTP request attributes

	private String clientIP; // X-Forwarded-For, not reliable and may be issues in K8S

	private String clientType; // HTTP User-Agent (as in most access logs)

	private String clientNetwork; // Client_Network HTTP header

	private String entryId; // HTTP Host header

	private String deviceId; // XTB device ID from client

	private String deviceIdAccepted; // XTB device ID in session

	private String gatewayIP; // X-Forwarded-For list where 2nd element identifies the entry hop

	private String url; // accessed service endpoint (drop when we start putting REST data into the URL may be)

	private String referrer; // HTTP Referer header for debugging and config addressing

	private String rpReferrer; // useful for network and RP analysis (typo by HTTP standard using referer fixed)

	private String applicationName; // AuthnRequest.ProviderName to handle RP-ID ambiguities

	private String oidcClientId; // allow correlation of a SAML flow with its OIDC initiator

	// Authentication process attributes

	private String clientName; // tenant (primary key clientExtId is handled via attribute definitions)

	private String profileExtId; // user profile selected

	private String billingId; // bookkeeping account for billing

	private String authLevel; // response only

	private String ctxClasses; // response only, better than authLevel because that's just config mostly

	private String scopes; // OIDC scopes

	private String issuer; // from message (authnrequest or response) in the end ourselves

	private String rpIssuer; // from state (authnrequest)

	private String cpIssuer; // from state (response)

	private String destination; // authnrequest only

	private String assertionConsumerUrl; // authnrequest only

	private Long loginDurationSecs; // seconds between login initiation and completion

	// correlation attributes

	private String messageId; // request based traceId potentially visible to user

	private String traceId; // request based traceId provided by perimeter

	private String conversationId; // conversation based traceId handled by XTB

	private String sessId; // SSO/SLO future use

	private String ssoSessionId; // external session mapped to http://trustbroker.swiss/claims/ssoSessionId

	private String ssoGroupName; // name of SSO group of SSO session

	private String ssoQoa; // QOA of the SSO session

	private Integer ssoParticipantCount; // number of participants  in SSO (Integer to allow null if no SSO)

	private Timestamp ssoEstablishedTime; // time when the SSO session was established

	// access request attributes

	private String arResponseId; // ID of the SAML response towards AR

	private String arState; // state of the AR

	private String arMode; // mode of the AR

	private String arReturnUrl; // return URL of the triggering application

	private Long arDurationSecs; // seconds between sending of AR and completion (includes user interaction for interactive case)

	private Timestamp expirationTime; // time when the session will expire

	// SAML Response attributes (contains many IdP related user attributes, see AttributeName.java)
	// Put this one at the end as Splunk stops indexing after 8k

	private Map<String, ResponseAttributeValues> responseAttributes; // FQ name in DEBUG level

	@CustomLogging
	private XMLObject samlMessage; // TRACE level

}
