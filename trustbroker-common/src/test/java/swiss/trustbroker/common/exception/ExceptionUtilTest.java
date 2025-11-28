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

package swiss.trustbroker.common.exception;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;

import java.io.IOException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

class ExceptionUtilTest {

	private static final String ROOT_MARKER = "root";

	@ParameterizedTest
	@MethodSource
	void isClientDisconnected(Exception ex, boolean expected) {
		assertThat(ExceptionUtil.isClientDisconnected(ex), is(expected));
	}

	static Object[][] isClientDisconnected() {
		return new Object[][] {
				{ new RuntimeException("Failed", new IOException(ExceptionUtil.BROKEN_PIPE)), true },
				{ new RuntimeException("Failed", new IOException("Other")), false },
				{ new RuntimeException("Failed", new IOException()), false },
				{ new RuntimeException("Failed", new IllegalArgumentException()), false },
				{ new IllegalArgumentException("Wrong",
						new RuntimeException(new IOException(ExceptionUtil.BROKEN_PIPE))), true },
		};
	}

	@ParameterizedTest
	@MethodSource
	void getRootCause(Exception ex) {
		assertThat(ExceptionUtil.getRootCause(ex).getMessage(), is(ROOT_MARKER));
		assertThat(ExceptionUtil.getRootMessage(ex), is(ROOT_MARKER));
	}

	static Object[][] getRootCause() {
		return new Object[][] {
				{ new RuntimeException(new IllegalArgumentException(ROOT_MARKER)) },
				{ new IOException(ROOT_MARKER) },
				{ new IllegalArgumentException(new RuntimeException(new IOException(ROOT_MARKER))), false },
		};
	}

	@Test
	void getRootCauseNull() {
		assertThat(ExceptionUtil.getRootCause(null), is(nullValue()));
		assertThat(ExceptionUtil.getRootMessage(null), is(nullValue()));
	}

}
