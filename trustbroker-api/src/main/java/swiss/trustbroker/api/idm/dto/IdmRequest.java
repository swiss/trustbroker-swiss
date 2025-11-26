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

import swiss.trustbroker.api.sessioncache.dto.AttributeName;

/**
 * Definition of the request to query the IDM.<br/>
 * (Corresponds to the RelyingParty IdmQuery configuration.)
 */
public interface IdmRequest {

	// query ID and type

	String getId();

	String getName();

	/**
	 * @return The name of the IDM store this request is targeting.
	 */
	String getStore();

	// attribute filters

	AttributeName getIssuerNameIdAttribute();

	AttributeName getSubjectNameIdAttribute();

	String getClientExtId();

	String getAppFilter();

	// user status handling

	boolean isFetchActiveOnly();

	// attribute selection

	List<AttributeName> getAttributeSelection();

	// callback

	String getUserStatusPolicy();
}
