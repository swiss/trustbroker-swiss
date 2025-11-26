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

import { Component, DestroyRef, OnInit } from '@angular/core';
import { ActivatedRoute, Params } from '@angular/router';

import { Theme } from '../model/Theme';
import { ApiService } from '../services/api.service';
import { ThemeService } from '../services/theme-service';
import { ValidationService } from '../services/validation-service';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

@Component({
	selector: 'app-error-page',
	templateUrl: './error-page.component.html',
	styleUrls: ['./error-page.component.scss'],
	standalone: false
})
export class ErrorPageComponent implements OnInit {
	titleKey: string;
	textKey: string;
	errorCode: string;
	infoKey: string;
	sessionId: string;
	continueButton: boolean;
	reloginButton: boolean;
	linkButton: boolean;
	supportInfo: boolean;
	referenceKey: string;
	reference: string;
	supportContactUrl: string;
	supportInfoText: string;
	supportContactText: string;
	theme: Theme;
	additionalInfoTitleKey: string;
	additionalInfoTextKey: string;

	constructor(
		private readonly route: ActivatedRoute,
		private readonly themeService: ThemeService,
		private readonly validation: ValidationService,
		private readonly apiService: ApiService,
		private readonly destroyRef: DestroyRef
	) {
		this.referenceKey = 'trustbroker.error.main.reference';
		this.theme = this.themeService.getTheme();
		this.themeService.subscribe({
			next: theme => {
				this.theme = theme;
			}
		});
	}

	ngOnInit(): void {
		this.route.params.pipe(takeUntilDestroyed(this.destroyRef)).subscribe((params: Params) => {
			this.errorCode = this.validation.getValidParameter(params, 'textKey', ValidationService.TEXT_KEY, 'default');
			this.titleKey = `trustbroker.error.main.title.${this.errorCode}`;
			this.infoKey = `trustbroker.error.main.info.${this.errorCode}`;

			this.additionalInfoTitleKey = `trustbroker.error.additional.title.${this.errorCode}`;
			this.additionalInfoTextKey = `trustbroker.error.additional.text.${this.errorCode}`;

			// default can be overridden via params:
			this.textKey = `trustbroker.error.main.text.${this.errorCode}`;
			this.supportContactUrl = `trustbroker.error.main.support.link.${this.errorCode}`;
			this.supportInfoText = `trustbroker.error.main.support.info.${this.errorCode}`;
			this.supportContactText = `trustbroker.error.main.support.contact.${this.errorCode}`;

			this.reference = this.validation.getValidParameter(params, 'reference', ValidationService.ID, '');
			this.sessionId = this.validation.getValidParameter(params, 'sessionId', ValidationService.ID, '');
			const buttonStr: string = this.validation.getValidParameter(params, 'button', ValidationService.ID, '');
			this.continueButton = buttonStr?.includes('continue');
			this.reloginButton = buttonStr?.includes('relogin');
			this.linkButton = buttonStr?.includes('link');
			this.supportInfo = buttonStr?.includes('support');
		});
	}

	imageUrl(image: string) {
		return this.apiService.getImageUrl(this.theme, image);
	}
}
