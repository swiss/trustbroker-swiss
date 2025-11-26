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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.Test;

class AccessRequestTest {

	@Test
	void getAllTriggerRolesEmpty() {
		assertThat(new AccessRequest().getAllTriggerRoles(), is(Collections.emptyMap()));
	}

	@Test
	void getAllTriggerRoles() {
		var ar = AccessRequest.builder()
							  .authorizedApplications(
									  givenAuthorizedApplications(List.of(
											  Pair.of("name1", "role1"),
											  Pair.of("name2", "role2"),
											  Pair.of("name1", "role3")
									  ))
							  )
							  .build();
		var expectedResult = Map.of("name1", "role1|role3", "name2", "role2");
		assertThat(ar.getAllTriggerRoles(), is(expectedResult));
	}


	static AuthorizedApplications givenAuthorizedApplications(List<Pair<String, String>> apps) {
		List<AuthorizedApplication> appList = new ArrayList<>();
		for (var app : apps) {
			appList.add(AuthorizedApplication.builder()
											 .name(app.getLeft())
											 .triggerRole(app.getRight())
											 .build());
		}
		return AuthorizedApplications.builder()
									 .authorizedApplicationList(appList)
									 .build();
	}


}
