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

import java.io.IOException;
import java.io.InputStream;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpHeaders;
import org.springframework.ws.soap.SoapMessageFactory;
import org.springframework.ws.soap.SoapVersion;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.springframework.ws.soap.saaj.SaajSoapMessageFactory;
import org.springframework.ws.transport.TransportInputStream;
import swiss.trustbroker.config.dto.WsTrustConfig;

/**
 * Workaround to support both SOAP 1.1 and 1.2.<br/>
 * This class determines the SOAP version via content-type header and dispatches to a SaajSoapMessageFactory configured
 * for the matching SOAP version.<br/>
 * The SOAP version from the inbound is stored in a thread local for use in the outbound (where we have no information).
 * If no outbound is sent due to an exception, the thread local is not cleared, but it is always set on the inbound.
 * SOAP 1.2 is used for an outbound without previous inbound.
 */
@Slf4j
public class DualProtocolSaajSoapMessageFactory implements SoapMessageFactory {

	private final SaajSoapMessageFactory messageFactorySoap11;

	private final SaajSoapMessageFactory messageFactorySoap12;

	private ThreadLocal<WsTrustConfig.SoapVersionConfig> soapVersionCache;

	public DualProtocolSaajSoapMessageFactory(@Qualifier("1.1") SaajSoapMessageFactory messageFactorySoap11,
			@Qualifier("1.2") SaajSoapMessageFactory messageFactorySoap12) {
		this.messageFactorySoap11 = messageFactorySoap11;
		this.messageFactorySoap12 = messageFactorySoap12;
		soapVersionCache = new ThreadLocal<>();
	}

	@Override
	public void setSoapVersion(SoapVersion version) {
		log.info("Setting SOAP version={} ignored", version);
	}

	// outbound
	@Override
	public SaajSoapMessage createWebServiceMessage() {
		var soapVersion = getSoapVersionFromThreadLocal();
		return factoryForVersion(soapVersion).createWebServiceMessage();
	}

	// inbound
	@Override
	public SaajSoapMessage createWebServiceMessage(InputStream inputStream) throws IOException {
		var soapVersion = getSoapVersionFromHeaders(inputStream);
		var result = factoryForVersion(soapVersion).createWebServiceMessage(inputStream);
		setSoapVersionInThreadLocal(soapVersion);
		return result;
	}

	private WsTrustConfig.SoapVersionConfig getSoapVersionFromThreadLocal() {
		var soapVersion = this.soapVersionCache.get();
		if (soapVersion == null) {
			soapVersion = WsTrustConfig.SoapVersionConfig.SOAP_1_2;
			log.info("Outbound: No SOAP version from inbound, using soapVersion={}", soapVersion);
		}
		else {
			this.soapVersionCache.remove();
			log.debug("Outbound: Using inbound soapVersion={} from thread local", soapVersion);
		}
		return soapVersion;
	}

	private void setSoapVersionInThreadLocal(WsTrustConfig.SoapVersionConfig soapVersion) {
		this.soapVersionCache.set(soapVersion);
		log.debug("Inbound: soapVersion={} stored in thread local", soapVersion);
	}

	private SaajSoapMessageFactory factoryForVersion(WsTrustConfig.SoapVersionConfig soapVersion) {
		return switch (soapVersion) {
			case SOAP_1_1 -> messageFactorySoap11;
			case SOAP_1_2, SOAP_1_X -> messageFactorySoap12; // SOAP_1_X cannot happen
		};
	}

	private static WsTrustConfig.SoapVersionConfig getSoapVersionFromHeaders(InputStream inputStream) throws IOException {
		if (inputStream instanceof TransportInputStream transportInputStream) {
			for (var headerValues = transportInputStream.getHeaders(HttpHeaders.CONTENT_TYPE); headerValues.hasNext(); ) {
				var headerValue = headerValues.next();
				if (headerValue.contains(SoapVersion.SOAP_11.getContentType())) {
					log.debug("Content-type={} is SOAP 1.1", headerValue);
					return WsTrustConfig.SoapVersionConfig.SOAP_1_1;
				}
				else if (headerValue.contains(SoapVersion.SOAP_12.getContentType())) {
					log.debug("Content-type={} is SOAP 1.2", headerValue);
					return WsTrustConfig.SoapVersionConfig.SOAP_1_2;
				}
			}
		}
		return WsTrustConfig.SoapVersionConfig.SOAP_1_2;
	}

	@Override
	public String toString() {
		return "DualProtocolSaajSoapMessageFactory{" +
				"messageFactorySoap11=" + messageFactorySoap11 +
				", messageFactorySoap12=" + messageFactorySoap12 +
				'}';
	}
}
