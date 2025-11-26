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

import { HttpErrorResponse } from '@angular/common/http';
import { ChangeDetectionStrategy, ChangeDetectorRef, Component, OnInit } from '@angular/core';
import { ActivatedRoute, Params, Router } from '@angular/router';

import { AnnouncementsService } from '../services/announcements.service';
import { AnnouncementResponse } from '../services/announcement-response';
import { ThemeService } from '../services/theme-service';
import { ValidationService } from '../services/validation-service';
import { Theme } from '../model/Theme';
import { map } from 'rxjs/operators';
import { Md5 } from 'ts-md5';
import { AnnouncementComponent } from './announcement/announcement.component';
import { TranslatePipe } from '@ngx-translate/core';
import { MatButton } from '@angular/material/button';
import { Configuration } from '../model/Configuration';
import { CookieService } from '../services/cookie-service';
import { ApiService } from '../services/api.service';

export type AnnouncementWithCookieName = AnnouncementResponse & { cookieName: string };

@Component({
	selector: 'app-announcements',
	templateUrl: './announcements.component.html',
	styleUrls: ['./announcements.component.scss'],
	standalone: true,
	changeDetection: ChangeDetectionStrategy.OnPush,
	imports: [AnnouncementComponent, TranslatePipe, MatButton]
})
export default class AnnouncementsComponent implements OnInit {
	showAnnouncements = false;
	announcements: AnnouncementWithCookieName[];
	appAccessible: boolean;
	theme: Theme;
	private authnRequestId: string;
	private issuer: string;
	private appName: string;
	private readonly config: Configuration = this.apiService.getConfiguration();

	constructor(
		private readonly announcementService: AnnouncementsService,
		private readonly route: ActivatedRoute,
		private readonly router: Router,
		private readonly themeService: ThemeService,
		private readonly validation: ValidationService,
		private readonly cookieService: CookieService,
		private readonly cd: ChangeDetectorRef,
		private readonly apiService: ApiService
	) {
		this.theme = this.themeService.getTheme();
		this.themeService.subscribe({
			next: theme => {
				this.theme = theme;
			}
		});
	}

	ngOnInit(): void {
		this.route.params.subscribe((params: Params) => {
			this.authnRequestId = this.validation.getValidParameter(params, 'authnRequestId', ValidationService.ID, '');
			this.issuer = this.validation.getValidParameter(params, 'issuer', ValidationService.ID, '');
			this.appName = this.validation.getValidParameter(params, 'appName', ValidationService.ID, '');
			const navRoute = `home/${this.issuer}/${this.authnRequestId}`;
			this.announcementService
				.getAnnouncements(this.issuer, this.appName)
				.pipe(
					map(responses => (responses ? responses.map(each => this.enhanceWithCookieName(each)) : [])),
					map(announcements => announcements.filter(announcement => !this.cookieService.check(announcement.cookieName)))
				)
				.subscribe({
					next: resp => {
						if (resp == null || resp.length === 0) {
							void this.router.navigate([navRoute]);
						} else {
							this.showAnnouncements = true;
						}
						this.cd.markForCheck();
						this.announcements = resp;
						this.appAccessible = resp.every(announcement => announcement.applicationAccessible);
					},
					error: (errorResponse: HttpErrorResponse) => {
						console.error(errorResponse);
						void this.router.navigate([navRoute]);
					}
				});
		});
	}

	continueToApp(): void {
		const navRoute = `home/${this.issuer}/${this.authnRequestId}`;
		void this.router.navigate([navRoute]);
	}

	private enhanceWithCookieName(announcement: AnnouncementResponse): AnnouncementWithCookieName {
		return {
			...announcement,
			cookieName: this.computeCookieName(announcement)
		};
	}

	private computeCookieName(announcement: AnnouncementResponse): string {
		return `${this.config.announcementCookie.name}-${new Md5().appendStr(JSON.stringify(announcement)).end()}`;
	}
}
