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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;

import org.junit.jupiter.api.Test;
import swiss.trustbroker.sessioncache.dto.SsoSessionParticipant;
import swiss.trustbroker.sessioncache.dto.SsoState;

class SsoStateTest {

	@Test
	void isRpParticipatingInSession() {
		var rpId = "rp2";
		var state = SsoState.builder().build();
		assertFalse(state.isRpParticipatingInSession(rpId));
		var participants = Set.of(givenSsoParticipant("rp1", "cp1"), givenSsoParticipant(rpId, "cp2"));
		state.setSsoParticipants(participants);
		assertTrue(state.isRpParticipatingInSession(rpId));
		assertFalse(state.isRpParticipatingInSession("rp3"));
		assertFalse(state.isRpParticipatingInSession(null));
	}

	private static SsoSessionParticipant givenSsoParticipant(String rpId, String cpId) {
		return SsoSessionParticipant.builder().cpIssuerId(cpId).rpIssuerId(rpId).build();
	}

}
