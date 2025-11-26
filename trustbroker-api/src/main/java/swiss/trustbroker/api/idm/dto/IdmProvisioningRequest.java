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

package swiss.trustbroker.api.idm.dto;

import java.util.List;
import java.util.Map;
import java.util.Set;

import lombok.Builder;
import lombok.Data;
import swiss.trustbroker.api.sessioncache.dto.AttributeName;

/**
 * Definition of the request to provision the IDM.
 */
@Builder
@Data
public class IdmProvisioningRequest {

	/**
	 * Claim to address the user in the IDM (not null).
	 */
	private final AttributeName identifyingClaim;

	/**
	 * The name in the IDM as filtering parameter for the IDM.
	 */
	private final String homeName;

	/**
	 * The account source from CP config
	 */
	private final String accountSource;

	/**
	 * Used for provisioning during migration from a CP to another.
	 * <br/>
	 * It is used to detect data from the source CP of the migration when provisioning for the target CP.
	 */
	private final String homeNameMigrationAlias;

	/**
	 * The subject name ID returned by the CP.
	 */
	private final String cpSubjectNameId;

	/**
	 * Quality of authentication provided by CP, mapped to the XTB order model.
	 */
	private final Integer cpAuthenticationQoa;

	/**
	 * If true, provisioning changes are only logged, not applied.
	 */
	private final boolean logOnly;

	/**
	 * Provisioning mode flags specific to implementations. All flags for all implementations are passed in.
	 */
	private final List<String> modes;

	/**
	 * Map of attributes received from the IDM (not null, not modifiable).
	 * <br/>
	 * Empty list if the user was not found by the <code>IdmQueryService</code>.
	 */
	private final Map<? extends AttributeName, List<String>> idmAttributes;

	/**
	 * Map of attributes received from the CP, to be provisioned in the IDM (not null, not modifiable).
	 */
	private final Map<? extends AttributeName, List<String>> cpAttributes;

	/**
	 * List of attributes to provision.
	 */
	private final List<? extends AttributeName> provisioningAttributes;

	/**
	 * This is not provided directly by the XTB core code, but is resulting from other custom interface implementations.
	 * <br/>
	 * The map key indicates the source of the data. It can be used by the implementations to match related interface
	 * implementations in order to share internal data structures such as lookup results.
	 * <br/>
	 * Currently the data returned by the <code>IdmQueryService</code> interface implementations is passed here.
	 *
	 * @see IdmResult#getAdditionalData()
	 */
	private final Map<Object, Object> additionalData;

	/**
	 * Returns the <code>IdmLookup</code> store(s) that were queried for the <code>additionalData</code>
	 * - including those that did not find a result.
	 * <br/>
	 * Currently the data returned by the <code>IdmQueryService</code> interface implementations is passed here.
	 *
	 * @since 1.12.0
	 * @see IdmResult#getQueriedStores()
	 */
	private final Set<String> queriedStores;

}
