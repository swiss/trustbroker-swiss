/*
 * Derivative work of original class from org.springframework.security:spring-security-oauth2-authorization-server:1.2.4:
 * org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenRevocationAuthenticationProvider
 *
 * https://spring.io/projects/spring-authorization-server
 *
 * License of original class:
 *
 * @license
 *
 * Copyright 2020-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package swiss.trustbroker.oidc;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opensaml.saml.saml2.core.Attribute;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;

@AllArgsConstructor
@Slf4j
public class Saml2TokenGenerator implements OAuth2TokenGenerator<OAuth2AccessToken> {

	private final RelyingParty relyingParty;

	private final TrustBrokerProperties trustBrokerProperties;

	@Override
	public OAuth2AccessToken generate(OAuth2TokenContext context) {

		var assertion = OpenSamlUtil.buildAssertionObject();
		var authorization = context.getAuthorization();
		if (authorization == null) {
			log.error("Authorization is null for SAML2 token generation");
			throw new IllegalArgumentException("Authorization is null for SAML2 token generation");
		}

		Map<String, Object> attributes = (HashMap) authorization.getAttributes().get("subjectTokenClaims");
		List<Attribute> attributeList = new ArrayList<>();
		for (Map.Entry<String, Object> entry : attributes.entrySet()) {
			var key = entry.getKey();
			var value = entry.getValue();
			if (value instanceof List<?> list) {
				var stringList = list.stream().map(Object::toString).toList();
				attributeList.add(SamlFactory.createAttribute(key, stringList, null));
			}
		}
		var attributeStatement = SamlFactory.createAttributeStatement(attributeList);
		assertion.getAttributeStatements().add(attributeStatement);

		var signatureParams = relyingParty.getSignatureParametersBuilder()
										  .credential(relyingParty.getRpSigner())
										  .skinnyAssertionNamespaces(trustBrokerProperties.getSkinnyAssertionNamespaces())
										  .build();
		SamlFactory.signAssertion(assertion, signatureParams);

		var encodedSaml = OpenSamlUtil.samlObjectToString(assertion);

		return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, encodedSaml, Instant.now(), Instant.now()
		);
	}

}
