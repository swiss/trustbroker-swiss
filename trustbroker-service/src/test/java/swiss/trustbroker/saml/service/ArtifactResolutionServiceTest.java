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

package swiss.trustbroker.saml.service;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import org.apache.commons.codec.binary.Hex;
import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.http.message.StatusLine;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.binding.artifact.SAML2ArtifactType0004;
import org.opensaml.saml.saml2.binding.artifact.SAML2ArtifactType0004Builder;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.security.credential.Credential;
import org.opensaml.soap.soap11.Body;
import org.opensaml.soap.soap11.Envelope;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import swiss.trustbroker.audit.dto.EventType;
import swiss.trustbroker.audit.service.AuditService;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.dto.ArtifactResolutionParameters;
import swiss.trustbroker.common.saml.service.ArtifactCacheService;
import swiss.trustbroker.common.saml.util.Base64Util;
import swiss.trustbroker.common.saml.util.OpenSamlUtil;
import swiss.trustbroker.common.saml.util.SamlFactory;
import swiss.trustbroker.common.saml.util.SamlInitializer;
import swiss.trustbroker.common.saml.util.SamlIoUtil;
import swiss.trustbroker.common.saml.util.SamlUtil;
import swiss.trustbroker.common.saml.util.SoapUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.config.dto.ArtifactResolution;
import swiss.trustbroker.config.dto.SamlProperties;
import swiss.trustbroker.config.dto.SecurityChecks;
import swiss.trustbroker.federation.xmlconfig.ArtifactBinding;
import swiss.trustbroker.federation.xmlconfig.ArtifactBindingMode;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.ProtocolEndpoints;
import swiss.trustbroker.federation.xmlconfig.RelyingParty;
import swiss.trustbroker.federation.xmlconfig.Saml;
import swiss.trustbroker.homerealmdiscovery.service.RelyingPartySetupService;
import swiss.trustbroker.test.saml.util.SamlTestBase;

@SpringBootTest
@ContextConfiguration(classes = ArtifactResolutionService.class)
class ArtifactResolutionServiceTest {

	private static final String AR_SERVICE_URL = "https://localhost:1/arp";

	private static final int AR_INDEX = 1;

	private static final String AR_ENTITY_ID = "arIssuerEntity";

	private static final String RP_ISSUER_ID = "rpIssuer1";

	private static final String CP_ISSUER_ID = "cpIssuer1";

	private static final String ARTIFACT_ID = "artifact1";

	private static final String ARTIFACT_RESOLVE_MESSAGE_ID = "arMsg1";

	@Autowired
	ArtifactResolutionService artifactResolutionService;

	@MockitoBean
	RelyingPartyService relyingPartyService;

	@MockitoBean
	TrustBrokerProperties trustBrokerProperties;

	@MockitoBean
	ArtifactCacheService artifactCacheService;

	@MockitoBean
	RelyingPartySetupService relyingPartySetupService;

	@MockitoBean
	AuditService auditService;

	@MockitoBean
	HttpClient httpClient;

	@MockitoBean
	ClassicHttpResponse httpResponse;

	@MockitoBean
	StatusLine httpStatusLine;

	@MockitoBean
	HttpEntity httpEntity;

	@BeforeAll
	static void setup() {
		SamlInitializer.initSamlSubSystem();
	}

	@BeforeEach
	void init() {
		var security = new SecurityChecks();
		security.setRequireSignedArtifactResolve(false);
		security.setRequireSignedArtifactResponse(false);
		doReturn(security).when(trustBrokerProperties).getSecurity();
	}

	@Test
	void decodeSamlArtifactRequest() throws Exception {
		// mock
		mockProperties();
		var artifactId = buildType04ArtifactId();
		var hexSourceId = Hex.encodeHexString(artifactId.getSourceID());
		var artifactIdEncoded = encodeType04ArtifactId(artifactId);
		var rpTrustCredentials = SamlTestBase.dummyCredentials();
		var saml = buildSaml();
		var rp = buildRelyingParty(saml);
		doReturn(Optional.of(rp)).when(relyingPartySetupService).getRelyingPartyByArtifactSourceIdOrReferrer(hexSourceId, null);
		var request = new MockHttpServletRequest();
		request.setParameter(SamlIoUtil.SAML_ARTIFACT_NAME, artifactIdEncoded);

		var samlResponse = SamlFactory.createRequest(AuthnRequest.class, RP_ISSUER_ID);
		var artifactResolve = buildArtifactResolve(ARTIFACT_ID, RP_ISSUER_ID, AR_SERVICE_URL);
		var artifactResponse = SamlFactory.createArtifactResponse(artifactResolve, Optional.of(samlResponse), AR_ENTITY_ID);
		SamlFactory.signSignableObject(artifactResponse, rp.getSignatureParametersBuilder().build());
		var envelope = SoapUtil.buildSoapEnvelope(artifactResponse);
		var envelopeStr = OpenSamlUtil.samlObjectToString(envelope);
		mockArtifactResolveSoapResponse(envelopeStr, artifactIdEncoded, rpTrustCredentials);

		// run
		var context = artifactResolutionService.decodeSamlArtifactRequest(request, Optional.of(httpClient));

		// check
		assertThat(context.getMessage(), instanceOf(AuthnRequest.class));
		var resolvedResponse = (AuthnRequest) context.getMessage();
		assertThat(resolvedResponse.getID(), is(samlResponse.getID()));
	}

	@Test
	void isRelyingPartyValid() {
		var saml = buildSaml();
		var binding = saml.getArtifactBinding();
		var rp = buildRelyingParty(saml);
		assertThat(ArtifactResolutionService.isRelyingPartyValid(Optional.of(rp)), is(true));

		// not supported
		saml.setArtifactBinding(ArtifactBinding.builder().inboundMode(ArtifactBindingMode.NOT_SUPPORTED).build());
		assertThat(ArtifactResolutionService.isRelyingPartyValid(Optional.of(rp)), is(false));

		// missing binding
		saml.setArtifactBinding(null);
		assertThat(ArtifactResolutionService.isRelyingPartyValid(Optional.of(rp)), is(true));

		// empty binding
		saml.setArtifactBinding(ArtifactBinding.builder().build());
		assertThat(ArtifactResolutionService.isRelyingPartyValid(Optional.of(rp)), is(true));

		// missing protocol endpoints
		saml.setArtifactBinding(binding);
		saml.setProtocolEndpoints(null);
		assertThat(ArtifactResolutionService.isRelyingPartyValid(Optional.of(rp)), is(false));

		// missing peer
		assertThat(ArtifactResolutionService.isRelyingPartyValid(Optional.empty()), is(false));
	}

	@Test
	void isClaimsPartyValid() {
		var saml = buildSaml();
		var binding = saml.getArtifactBinding();
		var cp = buildClaimsParty(saml);
		assertThat(ArtifactResolutionService.isClaimsPartyValid(Optional.of(cp)), is(true));

		// not supported
		saml.setArtifactBinding(ArtifactBinding.builder().inboundMode(ArtifactBindingMode.NOT_SUPPORTED).build());
		assertThat(ArtifactResolutionService.isClaimsPartyValid(Optional.of(cp)), is(false));

		// missing binding
		saml.setArtifactBinding(null);
		assertThat(ArtifactResolutionService.isClaimsPartyValid(Optional.of(cp)), is(true));

		// empty binding
		saml.setArtifactBinding(ArtifactBinding.builder().build());
		assertThat(ArtifactResolutionService.isClaimsPartyValid(Optional.of(cp)), is(true));

		// missing protocol endpoints
		saml.setArtifactBinding(binding);
		saml.setProtocolEndpoints(null);
		assertThat(ArtifactResolutionService.isClaimsPartyValid(Optional.of(cp)), is(false));

		// missing peer
		assertThat(ArtifactResolutionService.isClaimsPartyValid(Optional.empty()), is(false));
	}

	private static RelyingParty buildRelyingParty(Saml saml) {
		var rpSigner = SamlTestBase.dummyCredential();

		return RelyingParty.builder()
				.id(RP_ISSUER_ID)
				.rpSigner(rpSigner)
				.saml(saml)
				.build();
	}

	private static ClaimsParty buildClaimsParty(Saml saml) {
		return ClaimsParty.builder()
				.id(CP_ISSUER_ID)
				.saml(saml)
				.build();
	}

	private static Saml buildSaml() {
		return Saml.builder()
				.protocolEndpoints(
						ProtocolEndpoints.builder()
								.artifactResolutionIndex(AR_INDEX)
								.artifactResolutionUrl(AR_SERVICE_URL)
								.build()
				)
				.artifactBinding(
						ArtifactBinding.builder()
								.inboundMode(ArtifactBindingMode.SUPPORTED)
								.build()

				).build();
	}

	private void mockArtifactResolveSoapResponse(String responseContent, String artifactIdEncoded,
			List<Credential> trustCredentials) throws IOException {
		doReturn(new ByteArrayInputStream(responseContent.getBytes(StandardCharsets.UTF_8))).when(httpEntity).getContent();
		doReturn(HttpStatus.SC_OK).when(httpStatusLine).getStatusCode();
		doReturn(HttpStatus.SC_OK).when(httpResponse).getCode();
		doReturn(httpEntity).when(httpResponse).getEntity();
		doReturn(httpResponse).when(httpClient).executeOpen(eq(null),
				argThat(
					request -> validateInboundArtifactResolve(request, artifactIdEncoded, trustCredentials)
				),
				eq(null));
	}

	private static boolean validateInboundArtifactResolve(ClassicHttpRequest request, String artifactIdEncoded,
			List<Credential> trustCredentials) {
		try {
			assertThat(request.getUri().toString(), is(AR_SERVICE_URL));
			assertThat(request, instanceOf(HttpPost.class));
			var postRequest = (HttpPost) request;
			var artifactResolve =
					SoapUtil.extractSamlObjectFromEnvelope(postRequest.getEntity().getContent(), ArtifactResolve.class);
			assertThat(artifactResolve.getArtifact().getValue(), is(artifactIdEncoded));
			assertThat(artifactResolve.isSigned(), is(true));
			assertThat(SamlUtil.isSignatureValid(artifactResolve.getSignature(), trustCredentials), is(true));
			return true;
		}
		catch (IOException | URISyntaxException | UnsupportedOperationException ex) {
			throw new TechnicalException("ClassicHttpRequest validation failed: " + ex.getMessage(), ex);
		}
	}

	private static SAML2ArtifactType0004 buildType04ArtifactId() {
		var context = OpenSamlUtil.createMessageContext(null, null, null, null);
		var arParams = ArtifactResolutionParameters.of(AR_SERVICE_URL, AR_INDEX, AR_ENTITY_ID);
		OpenSamlUtil.initiateArtifactBindingContext(context, RP_ISSUER_ID, arParams);
		return new SAML2ArtifactType0004Builder().buildArtifact(context);
	}

	private static String encodeType04ArtifactId(SAML2ArtifactType0004 type) {
		var artifactIdBytes = new byte[44];
		System.arraycopy(type.getTypeCode(), 0, artifactIdBytes, 0, 2);
		System.arraycopy(type.getEndpointIndex(), 0, artifactIdBytes, 2, 2);
		System.arraycopy(type.getSourceID(), 0, artifactIdBytes, 4, 20);
		System.arraycopy(type.getMessageHandle(), 0, artifactIdBytes, 24, 20);
		return Base64Util.encode(artifactIdBytes, Base64Util.Base64Encoding.CHUNKED);
	}

	@Test
	void resolveArtifactFromRp() {
		// mock
		mockProperties();
		mockParties();

		var cachedMessage = SamlFactory.createResponse(Response.class, "messageIssuer1");
		doReturn(Optional.of(cachedMessage)).when(artifactCacheService).retrieveArtifact(ARTIFACT_ID);

		var request = buildArtifactResolveHttpRequest(RP_ISSUER_ID);
		var response = new MockHttpServletResponse();

		// run
		artifactResolutionService.resolveArtifact(request, response);

		// check
		var artifactResponse = SoapUtil.extractSamlObjectFromEnvelope(
				new ByteArrayInputStream(response.getContentAsByteArray()), ArtifactResponse.class);

		assertThat(artifactResponse.getStatus().getStatusCode().getValue(), is(StatusCode.SUCCESS));
		validateArtifactResponse(artifactResponse, RP_ISSUER_ID);
		assertThat(artifactResponse.getMessage(), instanceOf(cachedMessage.getClass()));
		var returnedMessage = (StatusResponseType) artifactResponse.getMessage();
		assertThat(returnedMessage.isSigned(), is(trustBrokerProperties.getSecurity().isDoSignArtifactResponse()));
		assertThat(returnedMessage.getID(), is(cachedMessage.getID()));
		validateAudit();
		verify(artifactCacheService).removeArtifact(ARTIFACT_ID);
	}

	@Test
	void resolveArtifactFromCp() {
		// mock
		mockProperties();
		mockParties();

		var cachedMessage = SamlFactory.createRequest(AuthnRequest.class, "messageIssuer1");
		doReturn(Optional.of(cachedMessage)).when(artifactCacheService).retrieveArtifact(ARTIFACT_ID);

		var request = buildArtifactResolveHttpRequest(CP_ISSUER_ID);
		var response = new MockHttpServletResponse();

		// run
		artifactResolutionService.resolveArtifact(request, response);

		// check
		var artifactResponse = SoapUtil.extractSamlObjectFromEnvelope(
				new ByteArrayInputStream(response.getContentAsByteArray()), ArtifactResponse.class);

		assertThat(artifactResponse.getStatus().getStatusCode().getValue(), is(StatusCode.SUCCESS));
		validateArtifactResponse(artifactResponse, CP_ISSUER_ID);
		assertThat(artifactResponse.getMessage(), instanceOf(cachedMessage.getClass()));
		var returnedMessage = (RequestAbstractType) artifactResponse.getMessage();
		assertThat(returnedMessage.isSigned(), is(trustBrokerProperties.getSecurity().isDoSignArtifactResponse()));
		assertThat(returnedMessage.getID(), is(cachedMessage.getID()));
		validateAudit();
		verify(artifactCacheService).removeArtifact(ARTIFACT_ID);
	}

	@Test
	void resolveArtifactMiss() {
		// mock
		mockProperties();
		mockParties();

		var request = buildArtifactResolveHttpRequest(RP_ISSUER_ID);
		var response = new MockHttpServletResponse();

		// run
		artifactResolutionService.resolveArtifact(request, response);

		// check
		var artifactResponse = SoapUtil.extractSamlObjectFromEnvelope(
				new ByteArrayInputStream(response.getContentAsByteArray()), ArtifactResponse.class);

		assertThat(artifactResponse.getStatus().getStatusCode().getValue(), is(StatusCode.RESOURCE_NOT_RECOGNIZED));
		validateArtifactResponse(artifactResponse, RP_ISSUER_ID);
		assertThat(artifactResponse.getMessage(), is(nullValue()));
		validateAudit();
	}

	private void mockParties() {
		var rp = RelyingParty.builder().id(RP_ISSUER_ID).rpSigner(SamlTestBase.dummyCredential()).build();
		doReturn(rp).when(relyingPartySetupService).getRelyingPartyByIssuerIdOrReferrer(RP_ISSUER_ID, null, true);
		doReturn(RP_ISSUER_ID).when(relyingPartyService).findRelyingPartyIdForTrustbrokerSamlObject(argThat(AuthnRequest.class::isInstance));
		var cp = ClaimsParty.builder().id(CP_ISSUER_ID).build();
		doReturn(cp).when(relyingPartySetupService).getClaimsProviderSetupByIssuerId(CP_ISSUER_ID, null, true);
	}

	private void mockProperties() {
		var ar = new ArtifactResolution();
		ar.setServiceUrl(AR_SERVICE_URL);
		ar.setIndex(AR_INDEX);
		var keystore = KeystoreProperties.builder()
				.signerCert(SamlTestBase.filePathFromClassPath(SamlTestBase.TEST_TB_KEYSTORE_JKS))
				.password(SamlTestBase.TEST_KEYSTORE_PW)
				.build();
		ar.setTruststore(keystore);
		ar.setKeystore(keystore);
		trustBrokerProperties.getSecurity().setDoSignArtifactResolve(true);
		var samlProperties = new SamlProperties();
		samlProperties.setArtifactResolution(ar);
		doReturn(samlProperties).when(trustBrokerProperties).getSaml();
		doReturn(AR_ENTITY_ID).when(trustBrokerProperties).getIssuer();
	}

	private static MockHttpServletRequest buildArtifactResolveHttpRequest(String issuerId) {
		var artifactResolve = buildArtifactResolve(ARTIFACT_ID, issuerId, AR_SERVICE_URL);
		var envelope = buildArtifactResolveEnvelope(artifactResolve);
		var requestString = OpenSamlUtil.samlObjectToString(envelope).getBytes(StandardCharsets.UTF_8);
		var request = new MockHttpServletRequest();
		request.setContent(requestString);
		return request;
	}

	private static Envelope buildArtifactResolveEnvelope(ArtifactResolve artifactResolve) {
		var envelope = OpenSamlUtil.buildSamlObject(Envelope.class);
		var body = OpenSamlUtil.buildSamlObject(Body.class);
		body.getUnknownXMLObjects().add(artifactResolve);
		envelope.setBody(body);
		return envelope;
	}

	private static ArtifactResolve buildArtifactResolve(String artifactId, String rpIssuerId, String arServiceUrl) {
		var artifact = SamlFactory.createArtifact(artifactId);
		var artifactResolve = SamlFactory.createArtifactResolve(artifact, rpIssuerId, arServiceUrl);
		artifactResolve.setID(ARTIFACT_RESOLVE_MESSAGE_ID);
		return artifactResolve;
	}

	private void validateArtifactResponse(ArtifactResponse artifactResponse, String issuerId) {
		assertThat(artifactResponse.getInResponseTo(), is(ARTIFACT_RESOLVE_MESSAGE_ID));
		assertThat(artifactResponse.getDestination(), is(issuerId));
		assertThat(artifactResponse.isSigned(), is(trustBrokerProperties.getSecurity().isDoSignArtifactResponse()));
	}

	private void validateAudit() {
		verify(auditService).logInboundFlow(argThat(dto -> dto.getEventType() == EventType.ARTIFACT_RESOLVE));
		verify(auditService).logOutboundFlow(argThat(dto -> dto.getEventType() == EventType.ARTIFACT_RESPONSE));
	}

}
