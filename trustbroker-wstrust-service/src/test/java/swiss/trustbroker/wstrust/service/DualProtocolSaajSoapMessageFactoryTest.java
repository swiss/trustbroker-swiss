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

package swiss.trustbroker.wstrust.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.io.IOException;
import java.util.Iterator;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.ws.soap.SoapVersion;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.springframework.ws.soap.saaj.SaajSoapMessageFactory;
import org.springframework.ws.transport.TransportInputStream;

@SpringBootTest
@ContextConfiguration(classes = DualProtocolSaajSoapMessageFactory.class)
class DualProtocolSaajSoapMessageFactoryTest {

	@MockitoBean
	@Qualifier("1.1")
	private SaajSoapMessageFactory mockFactory11;

	@MockitoBean
	@Qualifier("1.2")
	private SaajSoapMessageFactory mockFactory12;

	@MockitoBean
	private TransportInputStream stream;

	@MockitoBean
	private Iterator<String> iterator;

	@MockitoBean
	private SaajSoapMessage soapMessage;

	@Autowired
	private DualProtocolSaajSoapMessageFactory dualFactory;

	@Test
	void testOutboundOnly() {
		testOutbound(mockFactory12, mockFactory11);
	}

	@Test
	void testInboundSoapVersion11() throws IOException {
		testInbound(mockFactory11, SoapVersion.SOAP_11, mockFactory12);
	}

	@Test
	void testInboundSoapVersion12() throws IOException {
		testInbound(mockFactory12, SoapVersion.SOAP_12, mockFactory11);
	}

	@Test
	void testRoundtripSoapVersion11() throws IOException {
		testRoundtrip(mockFactory11, SoapVersion.SOAP_11, mockFactory12);
	}

	@Test
	void testRoundtripSoapVersion12() throws IOException {
		testRoundtrip(mockFactory12, SoapVersion.SOAP_12, mockFactory11);
	}

	private void testOutbound(SaajSoapMessageFactory usedFactory, SaajSoapMessageFactory unusedFactory) {
		doReturn(soapMessage).when(usedFactory).createWebServiceMessage();

		var result = dualFactory.createWebServiceMessage();

		assertThat(result, is(soapMessage));

		verifyNoMoreInteractions(unusedFactory);
	}

	private void testInbound(SaajSoapMessageFactory usedFactory, SoapVersion soapVersion,
			SaajSoapMessageFactory unusedFactory) throws IOException {
		doReturn(soapMessage).when(usedFactory).createWebServiceMessage(stream);
		doReturn(true).when(iterator).hasNext();
		doReturn(soapVersion.getContentType()).when(iterator).next();
		doReturn(iterator).when(stream).getHeaders(HttpHeaders.CONTENT_TYPE);

		var result = dualFactory.createWebServiceMessage(stream);

		assertThat(result, is(soapMessage));
		verifyNoMoreInteractions(unusedFactory);
	}

	private void testRoundtrip(SaajSoapMessageFactory usedFactory, SoapVersion soapVersion,
			SaajSoapMessageFactory unusedFactory) throws IOException {
		testInbound(usedFactory, soapVersion, unusedFactory);
		testOutbound(usedFactory, unusedFactory);
	}

}
