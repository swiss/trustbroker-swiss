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

package swiss.trustbroker.audit.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import swiss.trustbroker.audit.dto.AuditDto;

/**
 * Regular audit logger that audits all details.
 */
@Component
public class DefaultAuditLogger extends BaseAuditLogger {

	private class DefaultAuditLogFilter implements AuditLogFilter {

		@Override
		public boolean isAdditionalAuditingEnabled() {
			return getLogger().isTraceEnabled();
		}

		@Override
		public boolean suppressAttribute(String name, AuditDto.ResponseAttributeValue value) {
			return false;
		}

		@Override
		public boolean suppressField(String name, Object value) { return false; }
	}

	static final String AUDIT_LOGGER_NAME = AuditLogger.class.getName();

	static final String AUDIT_LOGGER_DETAILS_NAME = AUDIT_LOGGER_NAME + DETAILS_LOGGER_POSTFIX;

	@SuppressWarnings("java:S1312")
	private static final Logger log = LoggerFactory.getLogger(AUDIT_LOGGER_NAME);

	@SuppressWarnings("java:S1312")
	private static final Logger logDetail = LoggerFactory.getLogger(AUDIT_LOGGER_DETAILS_NAME);

	private final AuditLogFilter filter;

	public DefaultAuditLogger() {
		this.filter = new DefaultAuditLogFilter();
	}

	@Override
	protected Logger getLogger() {
		return log;
	}

	@Override
	protected Logger getDetailLogger() {
		return logDetail;
	}

	@Override
	public AuditLogBuilder createAuditLogBuilder(String prefix) {
		return new AuditLogBuilder(filter, prefix);
	}

	AuditLogFilter getFilter() {
		return filter;
	}

}
