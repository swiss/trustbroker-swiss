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

package swiss.trustbroker.test.util;

import java.util.Collections;
import java.util.List;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

public class MemoryAppender extends ListAppender<ILoggingEvent> {

	public void reset() {
		this.list.clear();
	}

	public boolean contains(String string, Level level) {
		return this.list.stream()
				.anyMatch(event -> event.getMessage().contains(string)
						&& event.getLevel().equals(level));
	}

	public int countEventsForLogger(String loggerName) {
		return (int) this.list.stream()
				.filter(event -> event.getLoggerName().contains(loggerName))
				.count();
	}

	public List<ILoggingEvent> search(String string) {
		return this.list.stream()
				.filter(event -> event.getMessage().contains(string))
				.toList();
	}

	public List<ILoggingEvent> search(String string, Level level) {
		return this.list.stream()
				.filter(event -> event.getMessage().contains(string) && event.getLevel().equals(level))
				.toList();
	}

	public int getSize() {
		return this.list.size();
	}

	public List<ILoggingEvent> getLoggedEvents() {
		return Collections.unmodifiableList(this.list);
	}

}
