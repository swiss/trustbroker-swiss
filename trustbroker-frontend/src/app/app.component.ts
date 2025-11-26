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

import { DOCUMENT } from '@angular/common';
import { Component, Inject } from '@angular/core';
import { Title } from '@angular/platform-browser';

import { Theme } from './model/Theme';
import { ApiService } from './services/api.service';
import { LanguageService } from './services/language.service';
import { ThemeService } from './services/theme-service';

@Component({
	selector: 'app-root',
	templateUrl: './app.component.html',
	styleUrls: ['./app.component.scss'],
	standalone: false
})
export class AppComponent {
	title = 'Trustbroker';
	theme: Theme;

	constructor(
		private readonly themeService: ThemeService,
		private readonly languageService: LanguageService,
		private readonly apiService: ApiService,
		private readonly titleService: Title,
		@Inject(DOCUMENT) private readonly doc: Document
	) {
		this.theme = this.themeService.getTheme();
		this.updateThemedElements();
		this.updateTitle();
		this.themeService.subscribe({
			next: theme => {
				this.theme = theme;
				this.updateThemedElements();
			}
		});
		this.triggerTranslations();
	}

	private triggerTranslations() {
		const titleKey = 'trustbroker.app.page.title';
		this.languageService.langChange$.subscribe(() => {
			const translated = this.languageService.translate(titleKey);
			if (translated !== titleKey) {
				this.title = translated;
				this.updateTitle();
			}
		});
	}

	private updateThemedElements() {
		this.updateFavicon();
	}

	private updateFavicon() {
		const faviconLink = this.doc.getElementById('favicon');
		if (faviconLink !== null) {
			faviconLink.setAttribute('href', this.apiService.getImageUrl(this.theme, 'favicon.ico'));
		}
	}

	private updateTitle() {
		this.titleService.setTitle(this.title);
	}
}
