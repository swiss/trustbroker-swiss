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

package swiss.trustbroker.saml.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import swiss.trustbroker.common.saml.util.CoreAttributeName;
import swiss.trustbroker.federation.xmlconfig.Definition;
import swiss.trustbroker.federation.xmlconfig.IdmLookup;
import swiss.trustbroker.federation.xmlconfig.IdmQuery;
import swiss.trustbroker.saml.dto.CpResponse;

public class ServiceTestBase {

	protected static final String PROFILE_ID = "123456";

	protected static final String PROFILE_ID2 = "123400";

	private static final String IDENTITY_QUERY = "IDENTITY";

	private static final String TENANT_QUERY = "TENANT";

	protected IdmLookup givenIdmLookup() {
		var clientExtId = "extId1";
		IdmQuery idmQuery1 = IdmQuery.builder().name(IDENTITY_QUERY).clientExtId(clientExtId).build();
		IdmQuery idmQuery2 = IdmQuery.builder().name(TENANT_QUERY).clientExtId(clientExtId).build();
		IdmQuery idmQuery3 = IdmQuery.builder().name(TENANT_QUERY).clientExtId(clientExtId).build();
		List<IdmQuery> queries = new ArrayList<>();
		queries.add(idmQuery1);
		queries.add(idmQuery2);
		queries.add(idmQuery3);

		IdmLookup idmLookup = new IdmLookup();
		idmLookup.setQueries(queries);

		return idmLookup;
	}

	protected CpResponse givenCpResponse(String issuer, String clientExtId, String homeName,
			String nameId, boolean addProperties) {
		CpResponse cpResponse = new CpResponse();
		cpResponse.setRpIssuer("urn:test:ANY");
		cpResponse.setNameId(nameId);
		cpResponse.setIdmLookup(givenIdmLookup());
		cpResponse.setIssuer(issuer);
		cpResponse.setHomeName(homeName);
		cpResponse.setClientExtId(clientExtId);
		if (addProperties) {
			cpResponse.setProperties(givenAttributes(issuer, clientExtId, homeName));
		}
		cpResponse.setAttribute(CoreAttributeName.HOME_NAME.getNamespaceUri(), "testhomename");

		return cpResponse;
	}

	protected Map<Definition, List<String>> givenAttributes(String issuer, String clientExtId, String homeName) {
		Map<Definition, List<String>> queryResponse = new HashMap<>();
		queryResponse.put(new Definition(CoreAttributeName.HOME_REALM), List.of(issuer));
		queryResponse.put(new Definition(CoreAttributeName.HOME_NAME), List.of(homeName));
		queryResponse.put(new Definition(CoreAttributeName.ISSUED_CLIENT_EXT_ID), List.of(clientExtId));
		return queryResponse;
	}

}
