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

import { Component, DestroyRef, Input, OnInit } from '@angular/core';
import { ApiService } from '../../services/api.service';
import { Theme } from '../../model/Theme';
import { ThemeService } from '../../services/theme-service';
import { SupportInfo } from '../../model/SupportInfo';
import { HttpErrorResponse } from '@angular/common/http';
import { LanguageService } from '../../services/language.service';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

@Component({
	selector: 'app-error-box',
	templateUrl: './error-box.component.html',
	styleUrls: ['./error-box.component.scss'],
	standalone: false
})
export class ErrorBoxComponent implements OnInit {
	@Input()
	titleKey: string;

	@Input()
	textKey: string;

	@Input()
	errorCode: string;

	@Input()
	infoKey: string;

	@Input()
	additionalInfoTitleKey: string;

	@Input()
	additionalInfoTextKey: string;

	@Input()
	referenceKey: string;

	@Input()
	reference: string;

	@Input()
	sessionId: string;

	@Input()
	continueButton: boolean;

	@Input()
	reloginButton: boolean;

	@Input()
	linkButton: boolean;

	@Input()
	supportInfo: boolean;

	@Input()
	supportInfoText: string;

	@Input()
	supportContactText: string;

	@Input()
	supportContactUrl: string;

	@Input()
	theme: Theme = ThemeService.defaultTheme;

	supportInfoData: SupportInfo;

	languageAppUrl: string;

	constructor(
		private readonly apiService: ApiService,
		private readonly languageService: LanguageService,
		private readonly destroyRef: DestroyRef
	) {}

	continueFlow(): void {
		this.apiService.continueResponseToRp(this.sessionId);
	}

	relogin(): void {
		this.apiService.relogin(this.sessionId);
	}

	followLink(): void {
		if (this.languageAppUrl) {
			window.location.href = this.languageAppUrl;
		}
	}

	ngOnInit(): void {
		this.setSupportInfoFlags(this.supportInfoText);

		if (this.supportInfo || this.linkButton) {
			this.apiService
				.fetchSupportInfo(this.errorCode, this.sessionId)
				.pipe(takeUntilDestroyed(this.destroyRef))
				.subscribe({
					next: resp => {
						this.supportInfoData = resp;
						this.setLanguageSpecificAppUrl();
					},
					error: (errorResponse: HttpErrorResponse) => {
						console.error(errorResponse);
						this.supportInfo = false;
						this.linkButton = false;
					}
				});
		}
	}

	setSupportInfoFlags(supportInfoText: string) {
		if (supportInfoText == null) {
			return;
		}
		this.languageService.langChange$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => {
			this.setLanguageSpecificAppUrl();
		});
	}

	setLanguageSpecificAppUrl() {
		if (this.supportInfoData?.appUrl) {
			this.languageAppUrl = this.supportInfoData.appUrl.replace('{lang}', this.languageService.currentLang);
		}
	}
}
