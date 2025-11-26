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

package swiss.trustbroker.oidcmock;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

// Remove the Security context after every successful authorization
public class SecurityContextOnAuthorizationFilter extends OncePerRequestFilter {

	private SecurityContextHolderStrategy securityContextHolderStrategy =
			SecurityContextHolder.getContextHolderStrategy();

	private final LogoutHandler logoutHandler = new CompositeLogoutHandler(
			new CookieClearingLogoutHandler("JSESSIONID"),
			new SecurityContextLogoutHandler()
	);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws
			ServletException, IOException {
		try {
			filterChain.doFilter(request, response);
		}
		finally {
			var locationHeader = response.getHeader(HttpHeaders.LOCATION);
			if (locationHeader != null) {
				var uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();
				if (uriComponents.getQueryParams().containsKey("code")) {
					var authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
					this.logoutHandler.logout(request, response, authentication);
				}
			}

		}
	}

}
