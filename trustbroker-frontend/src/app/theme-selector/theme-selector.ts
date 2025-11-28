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

import { Component, Input } from '@angular/core';

import { ApiService } from '../services/api.service';
import { ThemeService } from '../services/theme-service';

@Component({
	selector: 'app-theme-selector',
	templateUrl: './theme-selector.html',
	styleUrls: ['./theme-selector.scss'],
	standalone: false
})
export class ThemeSelectorComponent {
	@Input()
	theme = ThemeService.defaultTheme;

	constructor(
		private readonly themeService: ThemeService,
		private readonly apiService: ApiService
	) {}

	toggleTheme(): void {
		this.themeService.toggleTheme();
	}

	imageUrl(image: string) {
		return this.apiService.getImageUrl(this.theme, image);
	}
}
