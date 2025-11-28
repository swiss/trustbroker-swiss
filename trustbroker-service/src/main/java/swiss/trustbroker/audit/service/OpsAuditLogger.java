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

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.OpsAuditConfig;

/**
 * Audit logger for CID free logging.
 *
 * @see OpsAuditConfig
 */
@Component
@Slf4j
@ConditionalOnProperty(value = "trustbroker.config.audit.ops.enabled", havingValue = "true", matchIfMissing = false)
public class OpsAuditLogger extends BaseAuditLogger {

	@AllArgsConstructor
	private class OpsAuditFilter implements AuditLogFilter {

		private final TrustBrokerProperties trustBrokerProperties;

		@Override
		public boolean isAdditionalAuditingEnabled() {
			return getLogger().isTraceEnabled();
		}

		@Override
		public boolean suppressAttribute(String name, AuditDto.ResponseAttributeValue value) {
			return isAttributeCid(name, value);
		}

		private boolean isAttributeCid(String name, AuditDto.ResponseAttributeValue value) {
			if (value.getCid() != null) {
				return value.getCid();
			}
			var cid = getFieldCid(AuditDto.RESPONSE_ATTRIBUTES_NAME + '.' + name);
			if (cid != null) {
				return cid;
			}
			cid = getFieldCid(AuditDto.RESPONSE_ATTRIBUTES_NAME);
			if (cid != null) {
				return cid;
			}
			return false;
		}

		@Override
		public boolean suppressField(String name, Object value) {
			return isFieldCid(name);
		}

		boolean isFieldCid(String name) {
			var cid = getFieldCid(name);
			return Boolean.TRUE.equals(cid);
		}

		private Boolean getFieldCid(String name) {
			return trustBrokerProperties.getAudit().getOps().getCidFields().get(name);
		}
	}

	@SuppressWarnings("java:S1312")
	private static final Logger logDetail = LoggerFactory.getLogger(OpsAuditLogger.class.getName() + DETAILS_LOGGER_POSTFIX);

	private final OpsAuditFilter filter;

	public OpsAuditLogger(TrustBrokerProperties trustBrokerProperties) {
		filter = new OpsAuditFilter(trustBrokerProperties);
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
	protected boolean isDetailAuditingEnabled() {
		return super.isDetailAuditingEnabled() && !filter.suppressField(AuditDto.DETAIL_NAME, null);
	}

	@Override
	public AuditLogBuilder createAuditLogBuilder(String prefix) {
		return new AuditLogBuilder(filter, prefix);
	}

	AuditLogFilter getFilter() {
		return filter;
	}
}
