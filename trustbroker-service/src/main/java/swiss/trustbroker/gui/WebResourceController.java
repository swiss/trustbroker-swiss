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

package swiss.trustbroker.gui;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import swiss.trustbroker.homerealmdiscovery.service.WebResourceProvider;
import swiss.trustbroker.util.ApiSupport;

/**
 * Controller for web resources consumed bz the GUI.
 */
@Controller
@AllArgsConstructor
public class WebResourceController {

	private final WebResourceProvider resourceCache;

	@GetMapping(value = ApiSupport.IMAGES_URL + "/{name}")
	public void getImageByNameWithMediaType(
			HttpServletRequest request, HttpServletResponse response, @PathVariable("name") String imageName) {
		resourceCache.getImageByNameWithMediaType(request, response, imageName);
	}

	@GetMapping(value = ApiSupport.ASSETS_URL + "/**")
	public void getThemeAsset(HttpServletRequest request, HttpServletResponse response) {
		var path = request.getRequestURI();
		var resource = path.substring(ApiSupport.ASSETS_URL.length());
		resourceCache.getThemeAsset(request, response, resource);
	}

	// translations are generic, but we use the HRD namespace for now
	// NOTE: When ops messages or something else pops up, move this code to a TranslationService
	@GetMapping(value = ApiSupport.TRANSLATIONS_URL + "/{language}")
	public void getTranslationForLanguage(
			HttpServletRequest request, HttpServletResponse response, @PathVariable("language") String language) {
		resourceCache.getTranslationForLanguage(request, response, language);
	}

}
