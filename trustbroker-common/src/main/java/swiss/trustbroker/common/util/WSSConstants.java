/*
 * Derivative work of original class from org.apache.wss4j.wss4j-ws-security-common 3.0.1:
 * org.apache.wss4j.common.WSS4JConstants
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package swiss.trustbroker.common.util;

public class WSSConstants {

	// see org.apache.wss4j.dom.handler.WSHandlerConstants
	public static final String TIMESTAMP = "Timestamp";
	public static final String SIGNATURE = "Signature";

	public static final String SAML_TOKEN_SIGNED = "SAMLTokenSigned";
	public static final String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
	public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
	public static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";
	public static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";
	public static final String KEY_IDENTIFIER_ISSUER_SERIAL = "IssuerSerial";
	public static final String WST_NS_05_12 = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
	public static final String WSS_SAML2_KI_VALUE_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID";
	public static final String WSS_SAML_TOKEN_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1";
	public static final String WSS_SAML2_TOKEN_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

	// security token
	public static final String ENCODING_BASE64_BINARY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
	public static final String VALUE_X509_V3 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";

	private WSSConstants() {
	}
}
