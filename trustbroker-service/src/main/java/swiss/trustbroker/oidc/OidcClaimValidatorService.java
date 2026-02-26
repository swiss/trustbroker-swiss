/*
 * Copyright (C) 2026 trustbroker.swiss team BIT
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

package swiss.trustbroker.oidc;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.util.OidcUtil;
import swiss.trustbroker.config.TrustBrokerProperties;
import swiss.trustbroker.federation.xmlconfig.AcClass;
import swiss.trustbroker.federation.xmlconfig.ClaimsParty;
import swiss.trustbroker.federation.xmlconfig.OidcClient;
import swiss.trustbroker.federation.xmlconfig.QoaComparison;
import swiss.trustbroker.mapping.dto.QoaConfig;
import swiss.trustbroker.mapping.util.QoaMappingUtil;

/**
 * Service for validating claims from an OIDC CP.
 *
 * @see swiss.trustbroker.saml.util.AssertionValidator
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html#TokenResponseValidation">OIDC token response validation</a>
 */
@Service
@AllArgsConstructor
@Slf4j
public class OidcClaimValidatorService {

	private final TrustBrokerProperties trustBrokerProperties;

	private final Clock clock;

	public void validateClaims(JWTClaimsSet claims, ClaimsParty claimsParty, OidcClient client, String metadataIssuerId,
			String requestedNonce) {
		var issuer = claims.getIssuer();
		var expectedIssuer = client.getIssuerId();
		var expectedIssuerSource = "config";
		if (expectedIssuer == null) {
			expectedIssuerSource = "metadata";
			expectedIssuer = metadataIssuerId;
		}
		if (issuer == null || !issuer.equals(expectedIssuer)) {
			throw new RequestDeniedException(
					String.format(
							"Wrong issuer %s=%s  in OIDC %s from cpIssuerId=%s for client=%s expected issuer=%s from source=%s",
							OidcUtil.OIDC_ISSUER, issuer, OidcUtil.TOKEN_RESPONSE_ID_TOKEN,
							claimsParty.getId(), client.getId(), expectedIssuer, expectedIssuerSource));
		}
		validateSubAudAzp(claims, claimsParty.getId(), client);
		var now =  clock.millis();
		var expirationTime = claims.getExpirationTime();
		if (!validNotOnOrAfter(expirationTime, now)) {
			throw new RequestDeniedException(
					String.format("Expired OIDC %s expiration time %s=%s from cpIssuerId=%s for client=%s",
							OidcUtil.TOKEN_RESPONSE_ID_TOKEN, OidcUtil.OIDC_EXPIRATION_TIME, expirationTime,
							claimsParty.getId(), client.getId()));
		}
		var issuedAt = claims.getIssueTime();
		if (!validNotBefore(issuedAt, now)) {
			throw new RequestDeniedException(
					String.format("OIDC %s issued in the future from %s=%s cpIssuerId=%s for client=%s",
							OidcUtil.TOKEN_RESPONSE_ID_TOKEN, OidcUtil.OIDC_ISSUED_AT, issuedAt,
							claimsParty.getId(), client.getId()));
		}
		var notBefore = claims.getNotBeforeTime();
		if (!validNotBefore(notBefore, now)) {
			throw new RequestDeniedException(
					String.format("OIDC %s valid not before %s=%s from cpIssuerId=%s for client=%s",
							OidcUtil.TOKEN_RESPONSE_ID_TOKEN, OidcUtil.OIDC_NOT_BEFORE, notBefore,
							claimsParty.getId(), client.getId()));
		}
		if (requestedNonce == null) {
			// could be replay attack or a bug in state handling
			throw new RequestDeniedException(
					String.format("Missing requested nonce in session to validate OIDC %s from cpIssuerId=%s for client=%s",
							OidcUtil.TOKEN_RESPONSE_ID_TOKEN, claimsParty.getId(), client.getId()));
		}
		var nonce = claims.getClaim(OidcUtil.OIDC_NONCE);
		if (!requestedNonce.equals(nonce)) {
			throw new RequestDeniedException(
					String.format("Wrong nonce %s=%s in OIDC %s from cpIssuerId=%s for client=%s requestedNonce=%s",
							OidcUtil.OIDC_NONCE, nonce, OidcUtil.TOKEN_RESPONSE_ID_TOKEN,
							claimsParty.getId(), client.getId(), requestedNonce));
		}

		// OIDC_ACR checked later
		// optional:
		var jti = claims.getJWTID();
		if (jti == null) {
			log.debug("Missing JWT ID claim {} in OIDC {} from cpIssuerId={} for client={}",
					OidcUtil.OIDC_JWT_ID, OidcUtil.TOKEN_RESPONSE_ID_TOKEN,
					claimsParty.getId(), client.getId());
		}
	}

	public static void validateSubAudAzp(JWTClaimsSet claims, String counterPartyId, OidcClient client) {
		var subject = claims.getSubject();
		if (subject == null) {
			throw new RequestDeniedException(
					String.format("Missing subject claim %s in OIDC %s from cpIssuerId=%s for client=%s ",
							OidcUtil.OIDC_SUBJECT, OidcUtil.TOKEN_RESPONSE_ID_TOKEN,
							counterPartyId, client.getId()));
		}
		var audience = claims.getAudience();
		if (!audience.contains(client.getId())) {
			throw new RequestDeniedException(
					String.format("Wrong audience %s=%s in OIDC %s from cpIssuerId=%s expected clientId=%s",
							OidcUtil.OIDC_AUDIENCE, audience, OidcUtil.TOKEN_RESPONSE_ID_TOKEN,
							counterPartyId, client.getId()));
		}
		var authorizedParty = claims.getClaim(OidcUtil.OIDC_AUTHORIZED_PARTY);
		if (authorizedParty != null && !authorizedParty.equals(client.getId())) {
			throw new RequestDeniedException(
					String.format("Wrong authorized party %s=%s in OIDC %s from cpIssuerId=%s expected clientId=%s",
							OidcUtil.OIDC_AUTHORIZED_PARTY, authorizedParty, OidcUtil.TOKEN_RESPONSE_ID_TOKEN,
							counterPartyId, client.getId()));
		}
	}

	public static List<String> validateAcrs(JWTClaimsSet claims, ClaimsParty claimsParty, OidcClient client, TrustBrokerProperties trustBrokerProperties) {
		var acrs = claims.getClaim(OidcUtil.OIDC_ACR);
		if (acrs == null) {
			return Collections.emptyList();
		}

		List<String> acrStringList = getAcrStringList(acrs);

		var cpQoa = client.getQoa() != null ? client.getQoa() : claimsParty.getQoa();
		if (cpQoa == null) {
			log.debug("Missing Qoa config for issuer={} - skipping Qoa validation", claimsParty.getId());
			return acrStringList;
		}
		var configQoa = new QoaConfig(cpQoa, claimsParty.getId());
		QoaComparison comparison = configQoa.config().getComparison() != null ? configQoa.config().getComparison() : QoaComparison.EXACT;
		var expectedClasses = cpQoa.getClasses().stream()
								   .map(AcClass::getContextClass)
								   .toList();

		for (String acr : acrStringList) {
			QoaMappingUtil.validateContextClass(comparison, expectedClasses, configQoa, acr, configQoa, claimsParty.getId(), trustBrokerProperties.getQoaMap(), !cpQoa.getEnforce());
		}

		return acrStringList;
	}

	private static List<String> getAcrStringList(Object acrs) {
		List<String> acrStringList = new ArrayList<>();
		if (acrs instanceof Collection<?> acrList) {
			acrStringList = ((Collection<?>) acrList).stream()
													 .map(String::valueOf)
													 .toList();
		}
		else if (acrs instanceof String acr) {
			acrStringList = Collections.singletonList(acr);
		}
		return acrStringList;
	}

	boolean validNotBefore(Date check, long now) {
		if (check == null) {
			return true;
		}
		return now >= check.getTime() + trustBrokerProperties.getSecurity().getNotBeforeToleranceSec();
	}

	boolean validNotOnOrAfter(Date check, long now) {
		if (check == null) {
			return true;
		}
		return now < check.getTime() + trustBrokerProperties.getSecurity().getNotOnOrAfterToleranceSec();
	}
}
