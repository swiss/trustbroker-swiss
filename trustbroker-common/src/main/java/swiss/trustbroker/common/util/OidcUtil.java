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

package swiss.trustbroker.common.util;

import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.opensaml.security.credential.Credential;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.util.MimeType;
import swiss.trustbroker.common.exception.RequestDeniedException;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.oidc.JwkUtil;
import swiss.trustbroker.common.oidc.JwtUtil;
import swiss.trustbroker.common.saml.util.Base64Util;

@Slf4j
public class OidcUtil {

	public static final String DEFAULT_SCOPE = "openid"; // default scope (by default everything is in this, non-compliant)

	public static final String OIDC_CLIENT_ID = "client_id"; // OidcClientMetadataClaimNames.CLIENT_ID

	public static final String REDIRECT_URI = "redirect_uri"; // GET /authorize, /logout

	public static final String ID_TOKEN_HINT = "id_token_hint"; // GET /logout

	public static final String GRANT_TYPE = "grant_type"; // POST /token

	public static final String CODE = "code"; // POST /token

	public static final String CLIENT_SECRET = "client_secret"; // POST /token

	public static final String TOKEN_INTROSPECT = "token"; // GET /introspect

	public static final String ACCESS_INTROSPECT = "access_token"; // POST /userinfo e.g. by ruby adapter

	public static final String LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";

	public static final String OIDC_BEARER = "Bearer";

	public static final String HTTP_BASIC = "Basic";

	public static final String OIDC_BEARER_NULL = "Bearer null";

	public static final String OIDC_AUDIENCE = JWTClaimNames.AUDIENCE; // token claim matching client_id

	public static final String OIDC_AUTHORIZED_PARTY = "azp"; // alternate aud claim, if aud is multi-valued

	public static final String OIDC_SUBJECT = JWTClaimNames.SUBJECT; // subject (userExtId and sub_id are XTB alternates)

	public static final String OIDC_ACR_VALUES = "acr_values"; // requested QoA by client

	public static final String OIDC_ACR = "acr"; // acr claim

	public static final String OIDC_ISSUER = JWTClaimNames.ISSUER; // token claim

	public static final String OIDC_ISSUED_AT = JWTClaimNames.ISSUED_AT;

	public static final String OIDC_NOT_BEFORE = JWTClaimNames.NOT_BEFORE;

	public static final String OIDC_SID = "sid"; // sid claim

	public static final String OIDC_EXPIRATION_TIME = JWTClaimNames.EXPIRATION_TIME;

	public static final String OIDC_NONCE = "nonce";

	public static final String OIDC_JWT_ID = JWTClaimNames.JWT_ID;

	public static final String OIDC_STATE_ID = "state"; // client state transfer for clickbait prevention

	public static final String OIDC_ERROR = "error"; // error code according to spec

	public static final String OIDC_PROMPT = "prompt"; // client can force authentication...

	public static final String OIDC_PROMPT_NONE = "none";

	public static final String OIDC_PROMPT_LOGIN = "login"; // ...when setting prompt=login

	public static final String OIDC_PROMPT_ACCOUNT = "select_account";

	public static final String OIDC_SESSION_ID = "sid"; // token claim

	public static final String OIDC_SESSION_STATE = "session_state"; // token claim

	public static final String OIDC_TOKEN_TYPE = "typ"; // token claim (Keycloak specific, spec uses JWT as default)

	public static final String OIDC_SCOPE = "scope"; // scope claim

	public static final String OIDC_CODE = "code"; // PKCE code parameter

	public static final String OIDC_REFRESH_TOKEN = "refresh_token"; // non-PKCE

	public static final String OIDC_HEADER_KEYID = "kid";

	public static final String OIDC_HEADER_TYPE_JWT = "JWT";

	public static final String OIDC_HEADER_TYPE_JWE = "JWE";

	public static final String TOKEN_RESPONSE_ID_TOKEN = "id_token";

	public static final String TOKEN_RESPONSE_ACCESS_TOKEN = "access_token";

	public static final String TOKEN_RESPONSE_REFRESH_TOKEN = "refresh_token";

	public static final String TOKEN_RESPONSE_TOKEN_TYPE = "token_type";

	public static final String TOKEN_RESPONSE_EXPIRES_IN = "expires_in";

	public static final String CONTENT_TYPE_JWT = "application/jwt";

	public static final MimeType MIME_TYPE_JWT = MimeType.valueOf(CONTENT_TYPE_JWT);

	private OidcUtil() {
	}

	// https://openid.net/specs/openid-connect-frontchannel-1_0.html
	public static String appendFrontchannelLogoutQueryString(String url, String issuer, String oidcSessionId) {
		if (oidcSessionId == null || issuer == null) {
			// spec requires both or none:
			log.debug("oidcSessionId={} or issuer={} missing, not appending iss/sid", oidcSessionId, issuer);
			return url;
		}
		var params = new LinkedHashMap<String, String>(); // deterministic order mainly for tests
		params.put(OidcUtil.OIDC_ISSUER, issuer);
		params.put(OidcUtil.OIDC_SESSION_ID, oidcSessionId);
		return WebUtil.appendQueryParameters(url, params);
	}

	public static String getClientIdFromTokenClaims(Map<String, Object> claims) {
		// OIDC core 1.0, id_token spec (we are dealing with the authorization token here through usually, but it's the same)
		var azp = getClaimFromClaims(claims, OIDC_AUTHORIZED_PARTY); // OPTION: client_id
		if (azp == null) {
			// let's hope the client_id is actually the first element if LIST
			// ...as tokens are emitted by usm this is always true.
			azp = getClaimFromClaims(claims, OIDC_AUDIENCE); // REQUIRED: [ client_id, other ]
		}
		return azp;
	}

	public static String getClaimFromClaims(Map<String, Object> claims, String claimName) {
		String ret = null;
		if (claims != null) {
			var obj = claims.get(claimName);
			if (obj instanceof String str) {
				ret = str;
			} else if (obj instanceof List<?> list && !list.isEmpty()) {
				ret = list.get(0).toString(); // just try the first one ok (we expect clients to be aligned for /userinfo in RP
			}
		}
		return ret;
	}

	public static String getClientIdFromAuthorizationHeader(String header) {
		return getClaimFromAuthorizationHeader(header, OIDC_AUDIENCE);
	}

	public static String getSessionIdFromAuthorizationHeader(String bearer) {
		return getClaimFromAuthorizationHeader(bearer, OIDC_SESSION_ID);
	}

	private static String getUserFromBasicAuth(String basicAuthB64) {
		var basicAuth = new String(Base64Util.decode(basicAuthB64));
		return basicAuth.split(":")[0];
	}

	// https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
	// https://www.rfc-editor.org/rfc/rfc6749.html#section-2.3.1
	public static String getBasicAuthorizationHeader(String clientId, String clientSecret) {
		return HTTP_BASIC + ' ' + Base64Util.encode(
				WebUtil.urlEncodeValue(clientId) + ':' + WebUtil.urlEncodeValue(clientSecret),
				Base64Util.Base64Encoding.UNCHUNKED);
	}

	// https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
	// https://www.rfc-editor.org/rfc/rfc6750#section-2.1
	// accessToken must be JWT encoded: base64(header).base64(payload).base64(signature)
	public static String getBearerAuthorizationHeader(String accessToken) {
		return OIDC_BEARER + ' ' + accessToken;
	}

	private static String getClaimFromAuthorizationHeader(String header, String claimName) {
		if (header == null || header.isEmpty()) {
			return null;
		}
		var toks = header.split(" ");
		if (toks.length < 2) {
			log.debug("Ignoring {}={} to check for {}", HttpHeaders.AUTHORIZATION, header, claimName);
			return null;
		}
		if (toks[0].equalsIgnoreCase(OIDC_BEARER)) {
			return getClaimFromJwtToken(toks[1], claimName);
		}
		if (toks[0].equalsIgnoreCase(HTTP_BASIC) && claimName.equals(OIDC_AUDIENCE)) {
			return getUserFromBasicAuth(toks[1]);
		}
		log.debug("Ignoring unknown {}={} type", HttpHeaders.AUTHORIZATION, header);
		return null;
	}

	public static String getAuthorizationToken(String header, String token) {
		if (header != null && !header.isEmpty()) {
			var toks = header.split(" ");
			if (toks.length < 2) {
				log.debug("Ignoring {}={} to check", HttpHeaders.AUTHORIZATION, header);
				return null;
			}
			if (toks[0].equalsIgnoreCase(OIDC_BEARER) || toks[0].equalsIgnoreCase(HTTP_BASIC)) {
				return toks[1];
			}
		}
		if (token != null && !token.isEmpty()) {
			return token;
		}
		return null;
	}

	public static String getClientIdFromJwtToken(String jwtToken) {
		return getClaimFromJwtToken(jwtToken, OIDC_AUDIENCE);
	}

	public static String getSessionIdFromJwtToken(String jwtToken) {
		return getClaimFromJwtToken(jwtToken, OIDC_SESSION_ID);
	}

	public static String getClaimFromJwtToken(String jwtToken, String claimName) {
		var claims = getClaimsFromJwtToken(jwtToken);
		var claimValue = getClaimFromClaims(claims, claimName);
		log.debug("JWT token encountered with {}={}", claimName, claimValue);
		return claimValue;
	}

	public static Map<String, Object> getClaimsFromJwtToken(String jwtToken) {
		if (jwtToken == null) {
			return Collections.emptyMap();
		}
		var toks = jwtToken.split("\\.");
		// JWT token?
		if (toks.length != 3) { // yes
			if ("null".equals(jwtToken) || jwtToken.isEmpty()) { // some browser send that
				log.debug("Client sends empty '{}: {} {}'", HttpHeaders.AUTHORIZATION, OIDC_BEARER, jwtToken);
			} else {
				log.debug("Non-JWT token encountered: {}", jwtToken);
			}
			return Collections.emptyMap();
		}
		try {
			return JsonUtil.parseJsonObject(Base64Util.urlDecode(toks[1]), false);
		} catch (Exception ex) {
			log.info("Fishy JWT token encountered: {}", jwtToken, ex);
		}
		return Collections.emptyMap();
	}

	public static boolean isOidcPromptLogin(HttpServletRequest request) {
		if (request != null) {
			var prompt = request.getParameter(OidcUtil.OIDC_PROMPT);
			return OidcUtil.OIDC_PROMPT_LOGIN.equals(prompt) || OidcUtil.OIDC_PROMPT_ACCOUNT.equals(prompt);
		}
		return false;
	}

	public static List<String> getAcrValues(HttpServletRequest request) {
		var messageAcrValues = request != null ? request.getParameter(OidcUtil.OIDC_ACR_VALUES) : null;
		return convertAcrToContextClasses(messageAcrValues);
	}

	public static List<String> convertAcrToContextClasses(String messageAcrValues) {
		if (StringUtils.isNotEmpty(messageAcrValues)) {
			return Arrays.asList(messageAcrValues.split(" "));
		}
		return Collections.emptyList();
	}

	public static boolean isOidcPromptNone(HttpServletRequest request) {
		if (request != null) {
			var prompt = request.getParameter(OidcUtil.OIDC_PROMPT);
			return OidcUtil.OIDC_PROMPT_NONE.equals(prompt);
		}
		return false;
	}

	public static String getRedirectUriFromRequest(HttpServletRequest request) {
		var redirectUri = request.getParameter(OidcUtil.REDIRECT_URI);
		if (redirectUri == null) {
			redirectUri = request.getParameter(OidcUtil.LOGOUT_REDIRECT_URI);
		}
		return StringUtil.clean(redirectUri);
	}

	public static String getRealmFromRequestUrl(String requestUri) {
		if (requestUri == null) {
			return null;
		}
		int startInd = requestUri.lastIndexOf("/realms/");
		if (startInd < 0) {
			return null;
		}
		int endInd = requestUri.lastIndexOf("/protocol/");
		if (endInd < startInd) {
			return null;
		}
		return requestUri.substring(startInd + "/realms/".length(), endInd);
	}

	public static String maskedToken(String token) {
		if (token == null) {
			return token;
		}
		var toks = token.split("\\.");
		if (toks.length != 3) {
			return null;
		}
		return toks[0] + "." + toks[1] + "." + "SIG-MASKED";
	}

	// find OIDC grant or token helpful for debugging (data might not be related to use)
	public static String getGrantOrToken(HttpServletRequest request) {
		if (request == null) {
			return null;
		}
		var ret = new StringBuilder();
		var sep = "";
		for (var src : List.of(OIDC_CODE, OIDC_REFRESH_TOKEN, ID_TOKEN_HINT, TOKEN_INTROSPECT, ACCESS_INTROSPECT)) {
			var val = request.getParameter(src);
			if (val != null) {
				ret.append(sep)
						.append(src)
						.append("=")
						.append(val);
				sep = ",";
			}
		}
		for (var src : List.of(HttpHeaders.AUTHORIZATION)) {
			var val = request.getHeader(src);
			if (val != null) {
				ret.append(sep)
						.append(src)
						.append("=")
						.append(val);
			}
		}
		return ret.toString();
	}

	public static JWTClaimsSet verifyJwtToken(String jwtToken, Function<String, Optional<JWK>> keySupplier, String clientId) {
		try {
			var jwt = JWTParser.parse(jwtToken);

			// Plain JWT (not signed and not fully supported)
			if (jwt instanceof PlainJWT) {
				return jwt.getJWTClaimsSet();
			}

			if (!(jwt instanceof SignedJWT signedJwt)) {
				throw new RequestDeniedException(
						String.format("Unsupported JWT type from clientId=%s", clientId));
			}

			var header = signedJwt.getHeader();
			if (header.getKeyID() == null) {
				throw new RequestDeniedException(String.format("Missing keyId in token from=%s", clientId));

			}
			var kid = header.getKeyID();
			if (kid == null) {
				throw new RequestDeniedException(String.format("Invalid keyId=%s token from clientId=%s", kid, clientId));
			}
			var key = keySupplier.apply(kid);
			if (!key.isPresent()) {
				throw new RequestDeniedException(String.format("Missing key with keyId=%s from clientId=%s", kid, clientId));
			}
			var verifier = getVerifier(key.get().getKeyType(), key.get(), clientId);
			if (!signedJwt.verify(verifier)) {
				throw new RequestDeniedException(String.format("Invalid JWT token from clientId=%s", clientId));
			}
			return jwt.getJWTClaimsSet();
		} catch (ParseException | JOSEException ex) {
			throw new TechnicalException(
					String.format("Cannot parse JWT token from clientId=%s: %s", clientId, ex.getMessage()), ex);
		}
	}

	private static JWSVerifier getVerifier(KeyType keyType, JWK key, String clientId) throws JOSEException {
		if (keyType.equals(KeyType.EC)) {
			return new ECDSAVerifier(new ECKey.Builder(key.toECKey()).build());
		}
		if (keyType.equals(KeyType.RSA)) {
			return new RSASSAVerifier(new RSAKey.Builder(key.toRSAKey()).build());
		}
		throw new TechnicalException(String.format("KeyType=%s clientId=%s not supported", keyType, clientId));
	}

	// parse JWTClaimsSet from serialized JSON
	public static JWTClaimsSet parseJwtClaims(String jsonString) {
		if (StringUtils.isEmpty(jsonString)) {
			return new JWTClaimsSet.Builder().build();
		}
		try {
			var jsonObject = JsonUtil.parseJsonObject(jsonString, false);
			return JWTClaimsSet.parse(jsonObject);
		} catch (ParseException ex) {
			throw new TechnicalException(String.format("Could not parse JSON: %s", ex.getMessage()), ex);
		}
	}

	// combine two sets, values from primary win, either may be null
	public static JWTClaimsSet mergeJwtClaims(JWTClaimsSet primary, String primarySource,
											  JWTClaimsSet secondary, String secondarySource) {
		if (primary == null) {
			return secondary;
		}
		if (secondary == null) {
			return primary;
		}
		var claims = new JWTClaimsSet.Builder(secondary);
		for (var claim : primary.getClaims().entrySet()) {
			var overWritten = secondary.getClaim(claim.getKey());
			if (overWritten != null && !overWritten.equals(claim.getValue())) {
				log.info("Overwriting claim {}={} from secondarySource={} with value={} from primarySource={}",
						claim.getKey(), overWritten, secondarySource, claim.getValue(), primarySource);
			}
			claims.claim(claim.getKey(), claim.getValue());
		}
		return claims.build();
	}

	public static String generateNonce() {
		return UUID.randomUUID().toString().replace("-", "");
	}

	public static JWTClaimsSet decryptAndVerifyToken(String token, Function<String, Optional<JWK>> keySupplier, Credential credential, String clientId) {

		try {
			JWT jwt = JwtUtil.parseJWT(token);
			if (jwt instanceof EncryptedJWT) {
				var decryptJWT = JwtUtil.decryptJwt(token, credential, clientId);
				return OidcUtil.verifyJwtToken(decryptJWT.getPayload().toString(), keySupplier, clientId);
			} else {
				return OidcUtil.verifyJwtToken(token, keySupplier, clientId);
			}
		} catch (ParseException e) {
			throw new TechnicalException("Cannot decrypt JWT", e);
		} catch (JOSEException e) {
			throw new TechnicalException("Unexpected JOSE exception", e);
		}
	}

	public static Payload getAndSignPayload(JWTClaimsSet jwtClaimsSet, boolean singToken, JwsHeader jwsHeader,
											JWKSource<SecurityContext> jwkSource, String id) {
		var payload = jwtClaimsSet.toPayload();
		if (singToken) {
			var signingJwk = JwkUtil.selectJwk(JwkUtil.createJwkMatcher(jwsHeader, KeyUse.SIGNATURE, id), jwkSource);
			var header = jwsHeader;
			if (header.getKeyId() == null) {
				header = JwsHeader.from(jwsHeader).keyId(signingJwk.getKeyID()).build();
			}
			payload = JwtUtil.signJwt(header, jwtClaimsSet, signingJwk);
			log.debug("Signing Payload={} with key={}", payload, signingJwk.getKeyID());
		}
		return payload;
	}

	public static JWEHeader getJWEHeader(boolean requireTokenSignedEncryption, String encryptionAlgorithm,
										 String encryptionMethod, String kid) {
		var jweHeaderType = requireTokenSignedEncryption ? OidcUtil.OIDC_HEADER_TYPE_JWT : OidcUtil.OIDC_HEADER_TYPE_JWE;
		JWEHeader.Builder builder = new JWEHeader.Builder(EncryptionMethod.parse(encryptionMethod)).contentType(jweHeaderType);
		if (encryptionAlgorithm != null) {
			builder.alg(JWEAlgorithm.parse(encryptionAlgorithm));
		}
		if (kid != null) {
			builder.keyID(kid);
		}
		return builder.build();
	}

	public static boolean isIdToken(JwtEncoderParameters parameters) {
		var isIdToken = false;
		var claim = parameters.getClaims().getClaim(OidcUtil.OIDC_TOKEN_TYPE);
		if (claim != null) {
			isIdToken = "ID".equalsIgnoreCase(claim.toString());
		}
		return isIdToken;
	}

}
