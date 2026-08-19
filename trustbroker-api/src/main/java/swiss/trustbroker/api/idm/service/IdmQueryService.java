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

package swiss.trustbroker.api.idm.service;

import java.util.Map;
import java.util.Optional;

import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmRequests;
import swiss.trustbroker.api.idm.dto.IdmResult;
import swiss.trustbroker.api.relyingparty.dto.RelyingPartyConfig;
import swiss.trustbroker.api.sessioncache.dto.CpResponseData;

/**
 * Interface for querying an IDM service (e.g. via LDAP).
 * <br/>
 * An implementation can be configured via Spring @Value binding or by injecting swiss.trustbroker.config.TrustbrokerProperties
 * and using swiss.trustbroker.config.dto.IdmConfig (${trustbroker.config.idm}).
 * <br/>
 * Breaking changes:
 * <ul>
 *     <li>With 1.8.0 getAttributesFromIdm renamed to getAttributes.</li>
 *     <li>With 1.15.0 getAttributes and getAttributesAudited were changed to a single <code>IdmRequest</code> as input
 *     and state was added for implementations that need state across requests.</li>
 * </ul>
 */
public interface IdmQueryService {

	/**
	 * @param relyingPartyConfig   Data from the request (not null)
	 * @param cpResponse           Data from the CP response (not null)
	 * @param idmRequest           Defines the request to be performed by this call to query the IDM.
	 *                             <br/>
	 *                             The request is for this service.
	 * @param statusPolicyCallback callback for status policy enforcement
	 * @param state                State that can be used by this service across a set of related requests.
	 * @param result               Update with this query's result. Changing exising results is allowed.
	 * @return					   true if the query was processed, false otherwise
	 * @since 1.8.0
	 */
	boolean getAttributes(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse,
									  IdmRequest idmRequest, IdmStatusPolicyCallback statusPolicyCallback,
									  Map<String, Object> state, IdmResult result);

	/**
	 * Implements getAttributes as well but signals, that the IDM data is fetched based on a federated login
	 * for the first time and therefore might need additional auditing (write operations on an otherwise read-only access).
	 *
	 * @since 1.8.0
	 */
	default boolean getAttributesAudited(RelyingPartyConfig relyingPartyConfig, CpResponseData cpResponse,
			IdmRequest idmRequest, IdmStatusPolicyCallback statusPolicyCallback,
			Map<String, Object> state, IdmResult result) {
		return getAttributes(relyingPartyConfig, cpResponse, idmRequest, statusPolicyCallback, state, result);
	}

	/**
	 * @param idmRequests Defines the requests to be performed by the call to query the IDM.
	 * @return Client external ID if defined in <code>IdmRequests</code> and relevant for this service.
	 */
	default Optional<String> getClientExtId(IdmRequests idmRequests) {
		return Optional.empty();
	}

	/**
	 * @param requestedStore Defines the store requesting this check
	 * @param idmRequests Defines the requests to be performed by this call to query the store.
	 * @param defaultStore Default store of the application
	 * @return boolean whether those requests are interesting for this store.
	 */
	default boolean hasQueryOfStore(String requestedStore, IdmRequests idmRequests, String defaultStore) {
		return idmRequests != null && idmRequests.getQueryList() != null &&
				(requestedStore.equals(idmRequests.getStore())
						|| idmRequests.getQueryList().stream().anyMatch(q -> requestedStore.equals(q.getStore())
						|| idmRequests.getStore() == null && requestedStore.equals(defaultStore)));
	}

	/**
	 * @param requestedStore Defines the store requesting this check
	 * @param idmQuery Defines the request to be performed by this call to query the store.
	 * @param defaultStore Default store of the application
	 * @return boolean whether this particular request is interesting for this store.
	 */
	default boolean isQueryOfStore(String requestedStore, IdmRequest idmQuery, String defaultStore) {
		return requestedStore.equals(idmQuery.getStore())
				|| idmQuery.getStore() == null && requestedStore.equals(defaultStore);
	}

	/**
	 * @return the default order used by the service to determine the <code>IdmRequest</code>> order when no explicit order is set
	 * @since 1.15.0
	 */
	Integer getServiceDefaultOrder();

	/**
	 * @return the <code>IdmStore</code> name use to assign the correct <code>IdmService</code> to the <code>IdmRequest</code>
	 * @since 1.15.0
	 */
	String getStoreName();

	/**
	 * @return true if the  <code>IdmRequest</code> should be sorted by name when no explicit order is provided.
	 * <br/>
	 * Default: false
	 *
	 * @since 1.15.0
	 */
	default boolean sortQueriesByName() {
		return false;
	}
}
