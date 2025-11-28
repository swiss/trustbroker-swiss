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

import { ChangeDetectionStrategy, Component, Input, OnInit } from '@angular/core';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';

import { AlertType } from './AlertType';
import { Theme } from '../../model/Theme';
import { LanguageService } from '../../services/language.service';
import { ThemeService } from '../../services/theme-service';
import { AnnouncementWithCookieName } from '../announcements.component';
import { MatCheckbox, MatCheckboxChange } from '@angular/material/checkbox';
import { Configuration } from '../../model/Configuration';
import { CookieService } from '../../services/cookie-service';
import { ApiService } from '../../services/api.service';

@Component({
	selector: 'app-announcement',
	templateUrl: './announcement.component.html',
	styleUrls: ['./announcement.component.scss'],
	standalone: true,
	changeDetection: ChangeDetectionStrategy.OnPush,
	imports: [TranslatePipe, MatCheckbox]
})
export class AnnouncementComponent implements OnInit {
	@Input({ required: true })
	announcement: AnnouncementWithCookieName;

	@Input()
	theme: Theme = ThemeService.defaultTheme;

	title: string;
	message: string;
	alertType: string;
	contactUrl: string;

	private readonly config: Configuration = this.apiService.getConfiguration();

	constructor(
		private readonly languageService: LanguageService,
		private readonly translateService: TranslateService,
		private readonly cookieService: CookieService,
		private readonly apiService: ApiService
	) {}

	ngOnInit(): void {
		const currentLang = this.languageService.currentLang;
		this.updateText(currentLang);
		this.translateService.onLangChange.subscribe(event => this.updateText(event.lang));
		this.setAlertType();
	}

	// Low amount of announcements/application
	updateText(currentLang: string) {
		this.title = this.announcement.title[currentLang];
		this.message = this.announcement.message[currentLang];
		if (this.announcement.url) {
			this.contactUrl = this.announcement.url[currentLang];
		}
	}

	setAlertType() {
		if (this.announcement.type === 'MAINTENANCE') {
			this.alertType = AlertType.warning;
		} else if (this.announcement.type === 'INCIDENT') {
			this.alertType = AlertType.error;
		} else {
			this.alertType = AlertType.info;
		}
	}

	updateCookie(event: MatCheckboxChange) {
		if (event.checked) {
			this.cookieService.set(
				{
					...this.config.announcementCookie,
					name: this.announcement.cookieName
				},
				'read',
				this.announcement.validTo
			);
		} else {
			this.cookieService.delete(this.announcement.cookieName, this.config.announcementCookie.path);
		}
	}
}
