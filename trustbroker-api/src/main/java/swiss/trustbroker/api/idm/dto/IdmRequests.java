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

/**
 * Definition of the requests to perform for querying the IDM.<br/>
 * (Corresponds to the RelyingParty IdmLookup configuration.)
 * <br>
 * Potentially breaking changes:
 * <ul>
 *     <li>With 1.8.0 dropped <code>getMultiQueryPolicy</code> as <code>IdmService</code> is no longer expected to use this.</li>
 * </ul>
 */
public interface IdmRequests {

	/**
	 * Default store if not configured for the queries.
	 *
	 * @see IdmRequest#getStore()
	 */
	String getStore();

	List<IdmRequest> getQueryList();

}
