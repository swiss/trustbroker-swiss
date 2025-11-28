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

import java.util.Collections;
import java.util.List;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class SsoTest {

	@ParameterizedTest
	@MethodSource
	void logoutNotificationsEnabled(Boolean logoutNotifications, List<SloResponse> responses, boolean expected) {
		var sso = Sso.builder()
					 .logoutNotifications(logoutNotifications)
					 .sloResponse(responses)
					 .build();
		assertThat(sso.logoutNotificationsEnabled(), is(expected));
	}

	static Object[][] logoutNotificationsEnabled() {
		var response = SloResponse.builder().mode(SloMode.RESPONSE).build();
		var notify = SloResponse.builder().mode(SloMode.NOTIFY_TRY).build();
		return new Object[][] {
				// default
				{ null, null, false },
				{ null, Collections.emptyList(), false },
				// notifications override default
				{ null, List.of(response, notify), true },
				// explicit false wins
				{ false, Collections.emptyList(), false },
				{ false, List.of(notify), false },
				{ false, List.of(response, notify), false },
				// explicit true wins
				{ true, Collections.emptyList(), true },
				{ true, List.of(response), true },
		};
	}

}
