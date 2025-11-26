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

package swiss.trustbroker.wstrust.validator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.opensaml.soap.wsaddressing.Address;
import org.slf4j.LoggerFactory;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.saml.util.AssertionValidator;
import swiss.trustbroker.test.util.MemoryAppender;
import swiss.trustbroker.wstrust.dto.SoapMessageHeader;
import swiss.trustbroker.wstrust.util.WsTrustTestUtil;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.STRICT_STUBS)
class WsTrustHeaderValidatorTest {

	private static final String TEST_AUDIENCE = "http://localhost:8080";


	private MemoryAppender memoryAppender;

	private TrustBrokerProperties properties;

	private void enableDebug(Class clazz, MemoryAppender memoryAppender) {
		Logger logger = (Logger) LoggerFactory.getLogger(clazz);
		logger.setLevel(Level.DEBUG);
		logger.addAppender(memoryAppender);
	}

	@BeforeEach
	void setup() {
		// catch log output of interest
		memoryAppender = new MemoryAppender();
		memoryAppender.setContext((LoggerContext) LoggerFactory.getILoggerFactory());
		enableDebug(AssertionValidator.class, memoryAppender);
		enableDebug(WsTrustHeaderValidator.class, memoryAppender);
		memoryAppender.start();

		SamlInitializer.initSamlSubSystem();

		// security checks enabled, issue must be set
		properties = new TrustBrokerProperties();
		properties.setIssuer(TEST_AUDIENCE);
	}

	@AfterEach
	void cleanUp() {
		memoryAppender.reset();
		memoryAppender.stop();
	}

	@Test
	void validateHeaderElementsMissingHeaderTest() {
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsTrustHeaderValidator.validateHeaderElements(null, "validateHeaderElementsMissingHeaderTest-Issuer");
		});
		assertException("SOAP request header missing", ex);
	}

	@Test
	void validateHeaderElementsNoActionTest() {
		var requestHeader = WsTrustTestUtil.givenRequestHeader();
		requestHeader.setAction(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsTrustHeaderValidator.validateHeaderElements(requestHeader, "");
		});
		assertException("Action missing or invalid in SOAP header", ex);
	}

	@Test
	void validateHeaderElementsInvalidActionTest() {
		var requestHeader = WsTrustTestUtil.givenRequestHeader();
		requestHeader.getAction().setURI("http://invalidaction");
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsTrustHeaderValidator.validateHeaderElements(requestHeader, "");
		});
		assertException("Action missing or invalid in SOAP header", ex);
	}

	@Test
	void validateHeaderElementsInvalidActionSoap11Test() {
		var requestHeader = WsTrustTestUtil.givenRequestHeader();
		requestHeader.setAction(null);
		requestHeader.setSoapAction("http://invalidaction");
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsTrustHeaderValidator.validateHeaderElements(requestHeader, "");
		});
		assertException("Action missing or invalid in SOAP header", ex);
	}

	@Test
	void validateHeaderElementsNullMessageIdTest() {
		var requestHeader = WsTrustTestUtil.givenRequestHeader();
		requestHeader.setMessageId(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsTrustHeaderValidator.validateHeaderElements(requestHeader, "validateHeaderElementsNullMessageIdTest-Issuer");
		});
		assertException("MessageId missing in SOAP header", ex);
	}

	@Test
	void validateHeaderElementsNoMessageIdTest() {
		var requestHeader = WsTrustTestUtil.givenRequestHeader();
		requestHeader.setMessageId(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsTrustHeaderValidator.validateHeaderElements(requestHeader, "validateHeaderElementsNoMessageIdTest-Issuer");
		});
		assertException("MessageId missing in SOAP header", ex);
	}

	@Test
	void validateHeaderElementsNullReplayToTest() {
		var requestHeader = WsTrustTestUtil.givenRequestHeader();
		requestHeader.setReplyTo(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsTrustHeaderValidator.validateHeaderElements(requestHeader, "validateHeaderElementsNullReplayToTest-Issuer");
		});
		assertException("ReplyTo missing in SOAP header", ex);
	}

	@Test
	void validateHeaderElementsNullAddressTest() {
		var requestHeader = WsTrustTestUtil.givenRequestHeader();
		requestHeader.getReplyTo().setAddress(null);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsTrustHeaderValidator.validateHeaderElements(requestHeader, "");
		});
		assertException("Address missing or invalid in ReplyTo SOAP header", ex);
	}

	@Test
	void validateHeaderElementsNoAddressTest() {
		var requestHeader = WsTrustTestUtil.givenRequestHeader();
		requestHeader.getReplyTo().getAddress().setURI(Address.NONE);
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsTrustHeaderValidator.validateHeaderElements(requestHeader, "");
		});
		assertException("Address missing or invalid in ReplyTo SOAP header", ex);
	}

	@Test
	void validateHeaderElementsInvalidAddressTest() {
		var requestHeader = WsTrustTestUtil.givenRequestHeader();
		requestHeader.getReplyTo().getAddress().setURI("http://randomaddress");
		var ex = assertThrows(RequestDeniedException.class, () -> {
			WsTrustHeaderValidator.validateHeaderElements(requestHeader, "");
		});
		assertException("Address missing or invalid in ReplyTo SOAP header", ex);
	}

	@Test
	void validateHeaderElementsValidTest() {
		SoapMessageHeader requestHeader = WsTrustTestUtil.givenRequestHeader();
		assertDoesNotThrow(() -> {
			WsTrustHeaderValidator.validateHeaderElements(requestHeader, WsTrustTestUtil.TEST_TO);
		});
	}

	@Test
	void validateHeaderElementsValidSoap11Test() {
		SoapMessageHeader requestHeader = WsTrustTestUtil.givenRequestHeader();
		requestHeader.setSoapAction(requestHeader.getAction().getURI());
		requestHeader.setAction(null);
		assertDoesNotThrow(() -> {
			WsTrustHeaderValidator.validateHeaderElements(requestHeader, WsTrustTestUtil.TEST_TO);
		});
	}
	private void assertException(String expectedString, Exception ex) {
		assertTrue(((RequestDeniedException)ex).getInternalMessage().contains(expectedString),
				"'" + expectedString + "' not found in: " + ex.getMessage());
	}

}
