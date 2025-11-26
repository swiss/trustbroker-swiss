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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import swiss.trustbroker.audit.dto.AuditDto;
import swiss.trustbroker.config.TrustBrokerProperties;

class AuditLoggerTest {

	private Logger log = (Logger) LoggerFactory.getLogger(AuditLogger.class.getPackageName());

	private Level originalLevel = log.getLevel();

	private DefaultAuditLogger defaultAuditLogger = new DefaultAuditLogger();

	private TrustBrokerProperties properties = new TrustBrokerProperties();

	private OpsAuditLogger opsAuditLogger = new OpsAuditLogger(properties);

	@BeforeEach
	void setUp() {
		log.setLevel(Level.TRACE);
	}

	@AfterEach
	void tearDown() {
		log.setLevel(originalLevel);
	}

	@Test
	void testDefaultAuditLoggerNames() {
		assertThat(defaultAuditLogger.getLogger().getName(), is(DefaultAuditLogger.AUDIT_LOGGER_NAME));
		assertThat(defaultAuditLogger.getDetailLogger().getName(), is(DefaultAuditLogger.AUDIT_LOGGER_DETAILS_NAME));
	}

	@Test
	void testDefaultAuditLoggerDetailAuditingEnabled() {
		assertThat(defaultAuditLogger.isDetailAuditingEnabled(), is(true));
	}

	@Test
	void testOpsAuditLogger() {
		assertThat(opsAuditLogger.getLogger().getName(), is(OpsAuditLogger.class.getName()));
		var detailLoggerName = OpsAuditLogger.class.getName() + BaseAuditLogger.DETAILS_LOGGER_POSTFIX;
		assertThat(opsAuditLogger.getDetailLogger().getName(), is(detailLoggerName));
	}

	@Test
	void testOpsAuditLoggerDetailAuditingEnabled() {
		// log level based
		assertThat(opsAuditLogger.isDetailAuditingEnabled(), is(true));
		// CID overrides
		properties.getAudit().getOps().getCidFields().put(AuditDto.DETAIL_NAME, true);
		assertThat(opsAuditLogger.isDetailAuditingEnabled(), is(false));
		properties.getAudit().getOps().getCidFields().put(AuditDto.DETAIL_NAME, false);
		assertThat(opsAuditLogger.isDetailAuditingEnabled(), is(true));
	}

	@Test
	void testDefaultAuditFilterAdditionalAuditing() {
		var filter = defaultAuditLogger.getFilter();
		assertThat(filter.isAdditionalAuditingEnabled(), is(true));
		log.setLevel(Level.DEBUG);
		assertThat(filter.isAdditionalAuditingEnabled(), is(false));
	}

	@Test
	void testDefaultAuditFilterSuppressField() {
		var filter = defaultAuditLogger.getFilter();
		assertThat(filter.suppressField("any", null), is(false));
	}

	@Test
	void testDefaultAuditFilterSuppressAttribute() {
		var filter = defaultAuditLogger.getFilter();
		assertThat(filter.suppressAttribute("any", null), is(false));
	}

	@Test
	void testOpsAuditFilterAdditionalAuditing() {
		var filter = opsAuditLogger.getFilter();
		assertThat(filter.isAdditionalAuditingEnabled(), is(true));
		log.setLevel(Level.DEBUG);
		assertThat(filter.isAdditionalAuditingEnabled(), is(false));
	}

	@Test
	void testOpsAuditFilterSuppressField() {
		var filter = opsAuditLogger.getFilter();
		properties.getAudit().getOps().getCidFields().put("cid", true);
		properties.getAudit().getOps().getCidFields().put("normal", false);
		assertThat(filter.suppressField("cid", null), is(true));
		assertThat(filter.suppressField("normal", null), is(false));
		assertThat(filter.suppressField("undefined", null), is(false));
	}

	@Test
	void testOpsAuditFilterSuppressAttribute() {
		var filter = opsAuditLogger.getFilter();

		var cid = AuditDto.ResponseAttributeValue.of(null, null, null, null, true);
		assertThat(filter.suppressAttribute("cid", cid), is(true));

		var normal = AuditDto.ResponseAttributeValue.of(null, null, null, null, false);
		assertThat(filter.suppressAttribute("normal", normal), is(false));

		var none = AuditDto.ResponseAttributeValue.of(null, null, null, null, null);
		assertThat(filter.suppressAttribute("noneHardcodedDefault", none), is(false));

		properties.getAudit().getOps().getCidFields().put(AuditDto.RESPONSE_ATTRIBUTES_NAME, false);
		assertThat(filter.suppressAttribute("noneGlobalDefaultFalse", none), is(false));

		properties.getAudit().getOps().getCidFields().put(AuditDto.RESPONSE_ATTRIBUTES_NAME, true);
		assertThat(filter.suppressAttribute("noneGlobalDefaultTrue", none), is(true));

		properties.getAudit().getOps().getCidFields().clear();

		properties.getAudit().getOps().getCidFields().put(AuditDto.RESPONSE_ATTRIBUTES_NAME + ".cidAttribute", true);
		assertThat(filter.suppressAttribute("cidAttribute", none), is(true));

		properties.getAudit().getOps().getCidFields().put(AuditDto.RESPONSE_ATTRIBUTES_NAME + ".normalAttribute", false);
		assertThat(filter.suppressAttribute("normalAttribute", none), is(false));
	}
}
