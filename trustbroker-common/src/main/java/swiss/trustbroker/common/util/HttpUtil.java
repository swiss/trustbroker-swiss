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

package swiss.trustbroker.common.util;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.DefaultClientTlsStrategy;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import swiss.trustbroker.common.config.KeystoreProperties;
import swiss.trustbroker.common.exception.TechnicalException;
import swiss.trustbroker.common.saml.util.CredentialUtil;

/**
 * HTTP utility functions.
 * <br/>
 * XTB uses the Java HTTP client, but as OpenSAML uses the Apache HTTP client some API calls need that.
 */
@Slf4j
public class HttpUtil {

	public static final String SCHEME_HTTPS = "https";

	public static final String SCHEME_HTTP = "http";

	private HttpUtil() {
	}

	// Java HTTP client

	public static HttpClient createHttpClient(String scheme, KeystoreProperties truststoreParameters, Duration connectTimeout) {
		return createHttpClient(scheme, truststoreParameters, null, null, null, HttpClient.Version.HTTP_2, connectTimeout);
	}

	public static HttpClient createHttpClient(String scheme,
			KeystoreProperties truststoreParameters, KeystoreProperties keystoreParameters, String keystoreBasePath,
			URI proxyUri, HttpClient.Version protocolVersion, Duration connectTimeout) {
		var sslContext = createSslContext(scheme, truststoreParameters, keystoreParameters, keystoreBasePath);
		if (protocolVersion == null) {
			protocolVersion = HttpClient.Version.HTTP_1_1;
		}
		var proxySelector = createProxySelector(proxyUri);
		var builder = HttpClient.newBuilder()
				.sslContext(sslContext)
				.proxy(proxySelector)
				.version(protocolVersion);
		if (connectTimeout != null) {
			builder.connectTimeout(connectTimeout); // not nullable
		}
		return builder.build();
	}

	private static ProxySelector createProxySelector(URI proxyUri) {
		if (proxyUri == null) {
			return HttpClient.Builder.NO_PROXY;
		}
		return ProxySelector.of(InetSocketAddress.createUnresolved(proxyUri.getHost(), proxyUri.getPort()));
	}

	public static Optional<HttpResponse<String>> getHttpFormPostStringResonse(HttpClient httpClient, URI uri,
			Map<String, String> params, Map<String, String> headers) {
		return getHttpFormPostResponse(httpClient, uri, params, headers, HttpResponse.BodyHandlers.ofString());
	}

	public static Optional<String> getHttpFormPostString(HttpClient httpClient, URI uri,
			Map<String, String> params, Map<String, String> headers) {
		return checkAndMapResponse(getHttpFormPostResponse(httpClient, uri, params, headers, HttpResponse.BodyHandlers.ofString()));
	}

	public static Optional<InputStream> getHttpFormPostStream(HttpClient httpClient, URI uri,
			Map<String, String> params, Map<String, String> headers) {
		return checkAndMapResponse(getHttpFormPostResponse(httpClient, uri, params, headers, HttpResponse.BodyHandlers.ofInputStream()));
	}

	private static <T> Optional<HttpResponse<T>> getHttpFormPostResponse(HttpClient httpClient, URI uri,
			Map<String, String> params, Map<String, String> headers, HttpResponse.BodyHandler<T> bodyHandler) {
		var formPost = encodeFormParameters(params);
		var request = HttpRequest.newBuilder()
				.uri(uri)
				.POST(HttpRequest.BodyPublishers.ofString(formPost))
				.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
		return getHttpResponse(httpClient, uri, HttpMethod.POST, headers, bodyHandler, request);
	}

	public static Optional<String> getHttpString(HttpClient httpClient, URI uri, Map<String, String> headers) {
		return checkAndMapResponse(getHttpResponse(httpClient, uri,headers, HttpResponse.BodyHandlers.ofString()));
	}

	public static Optional<HttpResponse<String>> getHttpStringResponse(
			HttpClient httpClient, URI uri, Map<String, String> headers) {
		return getHttpResponse(httpClient, uri,headers, HttpResponse.BodyHandlers.ofString());
	}

	private static <T> Optional<HttpResponse<T>> getHttpResponse(HttpClient httpClient, URI uri, Map<String, String> headers,
			HttpResponse.BodyHandler<T> bodyHandler) {
		var request = HttpRequest.newBuilder()
				.uri(uri)
				.GET();
		return getHttpResponse(httpClient, uri, HttpMethod.GET, headers, bodyHandler, request);
	}

	private static <T> Optional<HttpResponse<T>> getHttpResponse(HttpClient httpClient,
			URI uri, HttpMethod method, Map<String, String> headers,
			HttpResponse.BodyHandler<T> bodyHandler, HttpRequest.Builder request) {
		headers.forEach(request::header);
		return fetchHttpResponse(httpClient, method, uri, request.build(), bodyHandler);
	}

	private static String encodeFormParameters(Map<String, String> params) {
		return params.entrySet()
				.stream()
				.map(entry -> entry.getKey() + "=" + WebUtil.urlEncodeValue(entry.getValue()))
				.collect(Collectors.joining("&"));
	}

	public static Optional<String> getHttpResponseString(HttpClient httpClient, URI uri) {
		return checkAndMapResponse(getHttpResponse(httpClient, uri, HttpResponse.BodyHandlers.ofString()));
	}

	public static Optional<InputStream> getHttpResponseStream(HttpClient httpClient, URI uri) {
		return checkAndMapResponse(getHttpResponse(httpClient, uri, HttpResponse.BodyHandlers.ofInputStream()));
	}

	private static <T> Optional<HttpResponse<T>> getHttpResponse(HttpClient httpClient, URI uri,
			HttpResponse.BodyHandler<T> bodyHandler) {
		var request = HttpRequest.newBuilder()
				.uri(uri)
				.GET()
				.build();
		return fetchHttpResponse(httpClient, HttpMethod.GET, uri, request, bodyHandler);
	}

	public static Optional<String> postHttpResponseString(HttpClient httpClient, URI uri, String body,
			Map<String, String> headers) {
		return checkAndMapResponse(postHttpResponse(httpClient, uri, body, headers));
	}

	public static Optional<HttpResponse<String>> postHttpResponse(HttpClient httpClient, URI uri, String body,
			Map<String, String> headers) {
		return submitHttpResponse(httpClient, uri, HttpMethod.POST,
				HttpRequest.BodyPublishers.ofString(body), headers,
				HttpResponse.BodyHandlers.ofString());
	}

	public static Optional<String> patchHttpResponseString(HttpClient httpClient, URI uri, String body,
			Map<String, String> headers) {
		return checkAndMapResponse(submitHttpResponse(httpClient, uri, HttpMethod.PATCH,
				HttpRequest.BodyPublishers.ofString(body), headers,
				HttpResponse.BodyHandlers.ofString()));
	}

	// POST, PATCH, PUT with body
	private static <T> Optional<HttpResponse<T>> submitHttpResponse(HttpClient httpClient, URI uri,
			HttpMethod method, HttpRequest.BodyPublisher bodyPublisher, Map<String, String> headers,
			HttpResponse.BodyHandler<T> bodyHandler) {
		var requestBuilder = HttpRequest.newBuilder()
				.uri(uri)
				.method(method.name(), bodyPublisher);
		if (headers != null) {
			headers.forEach(requestBuilder::header);
		}
		return fetchHttpResponse(httpClient, method, uri, requestBuilder.build(), bodyHandler);
	}

	private static <T> Optional<HttpResponse<T>> fetchHttpResponse(HttpClient httpClient,
			HttpMethod method, URI uri, // for tracing
			HttpRequest request, HttpResponse.BodyHandler<T> bodyHandler) {
		try {

			var response = httpClient.send(request, bodyHandler); // could use stream here
			if (response.statusCode() != HttpStatus.SC_OK) {
				log.error("HTTP {} uri={} returned HTTP statusCode={}", method, uri, response.statusCode());
				return Optional.of(response);
			}
			return Optional.of(response);
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			log.error("HTTP {} uri={} interrupted", method, uri);
			return Optional.empty();
		}
		catch (IOException ex) {
			log.error("HTTP {} uri={} failed with message={}", method, uri, ex.getMessage(), ex);
			return Optional.empty();
		}
	}

	private static <T> Optional<T> checkAndMapResponse(Optional<HttpResponse<T>> response) {
		if (response.isPresent() && response.get().statusCode() != HttpStatus.SC_OK) {
			return Optional.empty();
		}
		return response.map(HttpResponse::body);
	}

	// Apache HTTP client used by OpenSaml

	public static CloseableHttpClient createApacheHttpClient(String scheme,
			KeystoreProperties truststoreParameters, KeystoreProperties keystoreParameters,
			String keystoreBasePath, String proxyUrl, Duration connectTimeout) {
		var sslContext = createSslContext(scheme, truststoreParameters, keystoreParameters, keystoreBasePath);
		var httpProxy = createHttpProxy(proxyUrl);
		var sslSocketFactory = new DefaultClientTlsStrategy(sslContext);
		var cmBuilder = PoolingHttpClientConnectionManagerBuilder.create().setTlsSocketStrategy(sslSocketFactory);
		if (connectTimeout != null) {
			var connectionConfig = ConnectionConfig.custom().setConnectTimeout(Timeout.of(connectTimeout)).build();
			cmBuilder.setDefaultConnectionConfig(connectionConfig);
		}
		var cm = cmBuilder.build();
		return HttpClients.custom()
						  .setConnectionManager(cm)
						  .setProxy(httpProxy)
						  .build();
	}

	private static HttpHost createHttpProxy(String proxyUrl) {
		if (StringUtils.isEmpty(proxyUrl)) {
			return null;
		}
		try {
			var proxyUri = new URI(proxyUrl);
			return new HttpHost(proxyUri.getScheme(), proxyUri.getHost(), proxyUri.getPort());
		}
		catch (URISyntaxException ex) {
			throw new TechnicalException(String.format("Could not parse proxyUrl=%s message=%s", proxyUrl, ex.getMessage()), ex);
		}
	}

	private static SSLContext createSslContext(String scheme, KeystoreProperties truststoreParameters,
			KeystoreProperties keystoreParameters, String keystoreBasePath) {
		try {
			var builder = SSLContextBuilder.create();
			if (SCHEME_HTTPS.equals(scheme)) {
				if (truststoreParameters != null && StringUtils.isNotEmpty(truststoreParameters.getSignerCert())) {
					var password = CredentialUtil.processPassword(truststoreParameters.getPassword());
					builder.loadTrustMaterial(
							DirectoryUtil.absoluteFile(keystoreBasePath, truststoreParameters.getSignerCert()),
							CredentialUtil.passwordToCharArray(password));
				}
				if (keystoreParameters != null && StringUtils.isNotEmpty(keystoreParameters.getSignerCert())) {
					var password = CredentialUtil.processPassword(keystoreParameters.getPassword());
					builder.loadKeyMaterial(
							DirectoryUtil.absoluteFile(keystoreBasePath, keystoreParameters.getSignerCert()),
							CredentialUtil.passwordToCharArray(password),
							CredentialUtil.passwordToCharArray(password));
				}
			}
			return builder.build();
		}
		catch (FileNotFoundException ex) {
			throw new TechnicalException(String.format("truststoreParameters=%s keystoreParameters=%s not found for SSLContext",
					truststoreParameters, keystoreParameters), ex);
		}
		catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException |
			   UnrecoverableKeyException | KeyManagementException ex) {
			throw new TechnicalException(String.
					format("Building SSLContext failed for truststoreParameters=%s keystoreParameters=%s ",
							truststoreParameters, keystoreParameters), ex);
		}
	}

	public static int getDefaultPort(URI uri) {
		if (uri == null) {
			return -1;
		}
		return switch (uri.getScheme()) {
			case SCHEME_HTTP -> 80;
			case SCHEME_HTTPS -> 443;
			default -> -1;
		};
	}

}
