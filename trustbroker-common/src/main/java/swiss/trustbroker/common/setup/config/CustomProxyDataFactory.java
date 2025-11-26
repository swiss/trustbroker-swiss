/*
 * Derivative work of original class from org.eclipse.jgit.ssh.apache-6.8.0.202311291450-r:
 * org.eclipse.jgit.transport.sshd.DefaultProxyDataFactory
 *
 * https://www.eclipse.org/jgit/
 *
 * License of original class:
 *
 * Copyright (C) 2018, Thomas Wolf <thomas.wolf@paranor.ch> and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Distribution License v. 1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

package swiss.trustbroker.common.setup.config;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.eclipse.jgit.transport.sshd.ProxyData;
import org.eclipse.jgit.transport.sshd.ProxyDataFactory;
import swiss.trustbroker.common.exception.TechnicalException;

/**
 * An implementation of a ProxyDataFactory based on the CustomProxySelector.
 * org.eclipse.jgit.transport.sshd.DefaultProxyDataFactory
 *
 * Minor reformatting for code scanner issues.
 *
 * Original Javadoc:
 *
 * A default implementation of a {@link ProxyDataFactory} based on the standard
 * {@link java.net.ProxySelector}.
 *
 * @since 5.2
 */
public class CustomProxyDataFactory implements ProxyDataFactory {

	@Override
	public ProxyData get(InetSocketAddress remoteAddress) {
		try {
			// BEGIN customization
			var proxySelector = new CustomProxySelector();
			List<Proxy> proxies = proxySelector.select(new URI(remoteAddress.getHostString()));
			// END customization
			ProxyData data = getData(proxies, Proxy.Type.SOCKS);
			if (data == null) {
				proxies = ProxySelector.getDefault()
									   .select(new URI(Proxy.Type.HTTP.name(), "//" + remoteAddress.getHostString(),null));
				data = getData(proxies, Proxy.Type.HTTP);
			}
			return data;
		}
		catch (URISyntaxException e) {
			// customization
			throw new TechnicalException(String.format("Could not create proxy from remoteAddress=%s: %s",
					remoteAddress.getHostString(), e.getMessage()), e);
		}
	}

	private static ProxyData getData(List<Proxy> proxies, Proxy.Type type) {
		var proxy = proxies.stream()
				.filter(p -> type == p.type())
				.findFirst();
		if (proxy.isPresent()) {
			var proxyObj = proxy.get();
			var address = proxyObj.address();
			if (address instanceof InetSocketAddress) {
				return switch (type) {
					case HTTP, SOCKS -> new ProxyData(proxyObj);
					default -> null;
				};
			}
		}
		return null;
	}

}
