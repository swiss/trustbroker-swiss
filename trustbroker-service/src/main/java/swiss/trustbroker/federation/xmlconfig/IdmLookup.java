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

package swiss.trustbroker.federation.xmlconfig;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import swiss.trustbroker.api.idm.dto.IdmRequest;
import swiss.trustbroker.api.idm.dto.IdmRequests;
import swiss.trustbroker.api.idm.service.IdmQueryService;

/**
 * Specify a list of queries that are executed in the specified order.
 *
 * @see IdmQueryService
 */
@XmlRootElement(name = "IDMLookup")
@XmlAccessorType(XmlAccessType.FIELD)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class IdmLookup implements Serializable, IdmRequests {

	/**
	 * Used to select an IdmService implementation
	 */
	@XmlAttribute(name = "store")
	private String store;

	/**
	 * Handling of same attributes across queries.
	 * <br/>
	 * Default: MERGE is used if none is defined.
	 * <br/>
	 * Potentially breaking changes:
	 * <ul>
	 *     <li>With 1.8.0 changed from String to <code>MultiQueryResultPolicy</code>.</li>
	 * </ul>
	 */
	@XmlAttribute(name = "multiQueryPolicy")
	private MultiResultPolicy multiQueryPolicy;

	/**
	 * List of queries to be executed.
	 */
	@XmlElement(name = "IDMQuery", required = true)
	@Builder.Default
	private List<IdmQuery> queries = new ArrayList<>();

	// queries themselves are not cloned
	public IdmLookup shallowClone() {
		return new IdmLookup(store, multiQueryPolicy, new ArrayList<>(queries));
	}

	@JsonIgnore
	@Override
	public List<IdmRequest> getQueryList() {
		return Collections.unmodifiableList(queries);
	}

	public void updateIdmQueries(List<IdmRequest> idmRequests) {
		if (idmRequests == null) {
			queries = new ArrayList<>();
			return;
		}
		if (!idmRequests.equals(queries)) {
			queries = new ArrayList<>();
			for (var idmRequest : idmRequests) {
				queries.add(IdmQuery.of(idmRequest));
			}
		}
	}
}
