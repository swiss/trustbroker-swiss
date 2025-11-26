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

package swiss.trustbroker.wstrust.config;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Properties;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.xml.XMLConstants;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;

import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.ws.config.annotation.EnableWs;
import org.springframework.ws.config.annotation.WsConfigurerAdapter;
import org.springframework.ws.server.EndpointInterceptor;
import org.springframework.ws.soap.SoapMessageFactory;
import org.springframework.ws.soap.SoapVersion;
import org.springframework.ws.soap.saaj.SaajSoapMessageFactory;
import org.springframework.ws.soap.security.wss4j2.Wss4jSecurityInterceptor;
import org.springframework.ws.soap.security.wss4j2.support.CryptoFactoryBean;
import org.springframework.ws.soap.server.endpoint.SoapFaultDefinition;
import org.springframework.ws.soap.server.endpoint.SoapFaultMappingExceptionResolver;
import org.springframework.ws.transport.http.MessageDispatcherServlet;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CredentialUtil;
import swiss.trustbroker.common.util.WSSConstants;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.WsTrustConfig;
import swiss.trustbroker.exception.GlobalExceptionHandler;
import swiss.trustbroker.util.ApiSupport;
import swiss.trustbroker.wstrust.exception.DetailSoapFaultDefinitionExceptionResolver;
import swiss.trustbroker.wstrust.exception.ServiceFaultException;
import swiss.trustbroker.wstrust.service.CustomEndpointInterceptor;
import swiss.trustbroker.wstrust.service.DualProtocolSaajSoapMessageFactory;

@EnableWs
@Configuration
@Slf4j
@AllArgsConstructor
public class WebServiceConfiguration extends WsConfigurerAdapter {

	private final ResourceLoader resourceLoader;

	private final TrustBrokerProperties trustBrokerProperties;

	@Bean
	public static Transformer transformer() throws TransformerConfigurationException {
		TransformerFactory factory = TransformerFactory.newInstance();
		factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
		factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		return factory.newTransformer();
	}

	@Bean
	@ConditionalOnProperty(value = "trustbroker.config.wstrust.enabled", havingValue = "true", matchIfMissing = true)
	public ServletRegistrationBean<MessageDispatcherServlet> messageDispatcherServlet(ApplicationContext applicationContext) {
		var wsTrustConfig = trustBrokerProperties.getWstrust();
		var servlet = new MessageDispatcherServlet();
		servlet.setApplicationContext(applicationContext);
		servlet.setTransformWsdlLocations(true);
		var wsTrustConfigPath = wsTrustConfig.getWsBasePath();
		var paths = Stream.of(
								  // configured value
								  wsTrustConfigPath,
								  // XTB default
								  ApiSupport.WSTRUST_API,
								  // ADFS compatibility
								  ApiSupport.ADFS_WS_TRUST_ENTRY_URL,
								  ApiSupport.ADFS_WS_TRUST_COMPAT_URL,
								  wsTrustConfigPath + ApiSupport.ADFS_WS_TRUST_COMPAT_PATH
						  )
						  .collect(Collectors.toSet()); // Set.of does not allow duplicates
		log.info("Serving WS-Trust token requests on: {}", paths);
		return new ServletRegistrationBean<>(servlet, paths.toArray(String[]::new));
	}

	@Bean
	public SoapMessageFactory messageFactory(@Qualifier("1.1") SaajSoapMessageFactory messageFactory11,
			@Qualifier("1.2") SaajSoapMessageFactory messageFactory12) {
		var soapVersion = trustBrokerProperties.getWstrust().getSoapVersion();
		return switch (soapVersion) {
			case SOAP_1_1 -> messageFactory11;
			case SOAP_1_2 -> messageFactory12;
			case SOAP_1_X -> new DualProtocolSaajSoapMessageFactory(messageFactory11, messageFactory12);
		};
	}

	@Bean
	@Qualifier("1.1")
	public SaajSoapMessageFactory messageFactory11() {
		var messageFactory = new SaajSoapMessageFactory();
		messageFactory.setSoapVersion(SoapVersion.SOAP_11);
		return messageFactory;
	}

	@Bean
	@Qualifier("1.2")
	public SaajSoapMessageFactory messageFactory12() {
		var messageFactory = new SaajSoapMessageFactory();
		messageFactory.setSoapVersion(SoapVersion.SOAP_12);
		return messageFactory;
	}

	@SneakyThrows
	@Override
	public void addInterceptors(List<EndpointInterceptor> interceptors) {
		interceptors.add(new CustomEndpointInterceptor(trustBrokerProperties, transformer()));
		interceptors.add(securityInterceptor());
		super.addInterceptors(interceptors);
	}

	@Bean
	public Wss4jSecurityInterceptor securityInterceptor() throws Exception {

		Wss4jSecurityInterceptor securityInterceptor = new Wss4jSecurityInterceptor();
		securityInterceptor.setValidateResponse(true);
		// Set response security header config
		var securementActions = WSSConstants.TIMESTAMP;
		// 5 min
		securityInterceptor.setSecurementTimeToLive(300);
		// NOTE time to live set has a bug in spring ws. Workaround: https://jira.spring.io/browse/SWS-1084?redirect=false
		securityInterceptor.setValidationTimeToLive(500000);
		securityInterceptor.setFutureTimeToLive(50000);

		var wsTrustConfig = trustBrokerProperties.getWstrust();
		if (wsTrustConfig.isDoSignResponse()) {
			log.info("Enabling RSTR signature");
			securementActions += " " + WSSConstants.SIGNATURE;
			securityInterceptor.setSecurementPassword(wsTrustConfig.getPassword());
			securityInterceptor.setSecurementSignatureCrypto(serverKeyStoreCryptoFactoryBean().getObject());
			securityInterceptor.setSecurementSignatureUser(wsTrustConfig.getAlias());
			securityInterceptor.setSecurementSignatureAlgorithm(WSSConstants.RSA_SHA256);
			securityInterceptor.setSecurementSignatureDigestAlgorithm(WSSConstants.SHA256);
			securityInterceptor.setSecurementSignatureKeyIdentifier(WSSConstants.KEY_IDENTIFIER_ISSUER_SERIAL);
			// body is the default - format {Element|Content}{elementNamespace}{elementName} see WSS4J JavaDoc
			securityInterceptor.setSecurementSignatureParts("{}{}Body");
		}
		else {
			log.info("RSTR signature disabled");
		}

		securityInterceptor.setSecurementActions(securementActions);

		// Optionally enable signature check.
		// Our implementation has some issue with running assertion validations multiple times.
		// We therefore disable checks on WSS4J level leading to better control on integration problems.
		// To improve security by re-enabling wss4j checks we need to:
		// - Improve WSS4J error handling giving details about what failed without the need to DEBUG
		// - Duplicate signature validation not leading to NPE on certs[0] in Merlin.verifyTrust
		// ...or just drop wss4j and rely XTB SAML processing as the feature was disabled since 1.0.
		if (trustBrokerProperties.getSecurity().isValidateSecurityTokenRequest()) {
			securityInterceptor.setValidationActions(trustBrokerProperties.getSecurity().getWss4jChecks());
			securityInterceptor.setValidationSignatureCrypto(serverKeyStoreCryptoFactoryBean().getObject());
		}
		else {
			log.info("Using XTB only mode only to validate incoming SOAP security SAML assertion. "
					+ "WSS4J security check for incoming WS-Trust requests is disabled "
					+ "with trustbroker.config.security.validateSecurityTokenRequest=false.");
		}

		return securityInterceptor;
	}

	@Bean
	@ConditionalOnExpression(
			"#{${trustbroker.config.security.validateSecurityTokenRequest:true} or ${trustbroker.config.wstrust.doSignResponse:true}}")
	public CryptoFactoryBean serverKeyStoreCryptoFactoryBean() throws IOException {
		var wsTrustConfig = trustBrokerProperties.getWstrust();
		var cert = wsTrustConfig.getCert();
		if (cert == null) {
			throw new TechnicalException("Missing trustbroker.config.wstrust.cert");
		}
		var absolutePath = new File(cert).getAbsolutePath();
		var resource = resourceLoader.getResource("file:" + absolutePath);
		if (!resource.exists()) {
			throw new TechnicalException(
					String.format("Resource for signature validation not found at %s", resource.getDescription()));
		}
		CryptoFactoryBean cryptoFactoryBean = new CryptoFactoryBean();
		cryptoFactoryBean.setKeyStoreLocation(resource);
		String password = CredentialUtil.processPassword(wsTrustConfig.getPassword());
		cryptoFactoryBean.setKeyStorePassword(password);
		return cryptoFactoryBean;
	}

	@Bean
	public SoapFaultMappingExceptionResolver exceptionResolver(GlobalExceptionHandler globalExceptionHandler) {
		SoapFaultMappingExceptionResolver exceptionResolver = new DetailSoapFaultDefinitionExceptionResolver(globalExceptionHandler);

		SoapFaultDefinition faultDefinition = new SoapFaultDefinition();
		faultDefinition.setFaultCode(SoapFaultDefinition.SERVER);
		exceptionResolver.setDefaultFault(faultDefinition);

		Properties errorMappings = new Properties();
		errorMappings.setProperty(Exception.class.getName(), SoapFaultDefinition.SERVER.toString());
		errorMappings.setProperty(ServiceFaultException.class.getName(), SoapFaultDefinition.SERVER.toString());
		exceptionResolver.setExceptionMappings(errorMappings);
		exceptionResolver.setOrder(1);
		return exceptionResolver;
	}

}
