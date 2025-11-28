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

import { BreakpointObserver } from '@angular/cdk/layout';
import { HttpErrorResponse, HttpResponse } from '@angular/common/http';
import { Component, DestroyRef, effect, input } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';

import { environment } from '../../environments/environment';
import { IdpObjects } from '../model/IdpObject';
import { ApiService } from '../services/api.service';
import { IdpObjectService } from '../services/idp-object.service';
import { LanguageService } from '../services/language.service';
import { ThemeService } from '../services/theme-service';
import { ValidationService } from '../services/validation-service';
import { Observable, switchMap } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { map } from 'rxjs/operators';

@Component({
	selector: 'app-hrd-cards',
	templateUrl: './hrd-cards.component.html',
	styleUrls: ['./hrd-cards.component.scss'],
	standalone: false
})
export class HrdCardsComponent {
	idpObjects = input.required<IdpObjects>();

	showHrd = true;
	baseUrl: string = environment.apiUrl;
	showNormalSize$: Observable<boolean>;
	clicked: boolean;

	protected readonly ThemeService = ThemeService;

	constructor(
		private readonly apiService: ApiService,
		breakpointObserver: BreakpointObserver,
		private readonly idpObjectService: IdpObjectService,
		public readonly languageService: LanguageService,
		public readonly themeService: ThemeService,
		private readonly validation: ValidationService,
		private readonly route: ActivatedRoute,
		private readonly router: Router,
		private readonly destroyRef: DestroyRef
	) {
		effect(() => {
			if (this.idpObjects().tiles?.length === 1 && !this.idpObjects().tiles[0].disabled) {
				this.showHrd = false;
				this.onClickCard(this.idpObjects().tiles[0]);
			} else {
				// disabled tiles are also displayed in help
				this.idpObjectService.addIdpObjects(this.idpObjects().tiles);
			}
		});

		this.showNormalSize$ = breakpointObserver.observe(['(min-width: 600px)']).pipe(map(({ matches }) => matches));
	}

	getImageUrl(imageName): string {
		const currentLang = this.languageService.currentLang;
		const newImgName = imageName.replace('{language}', currentLang);

		return `${this.baseUrl}hrd/images/${newImgName}`;
	}

	onClickCard(idpObject): void {
		if (this.clicked || idpObject.disabled) {
			return;
		}
		this.clicked = true;
		this.route.params
			.pipe(
				switchMap(params => this.apiService.selectIdp(this.validation.getValidParameter(params, 'authnRequestId', ValidationService.ID, ''), idpObject.urn)),
				takeUntilDestroyed(this.destroyRef)
			)
			.subscribe({
				next: resp => {
					this.processSelectionResponse(resp);
				},
				error: (errorResponse: HttpErrorResponse) => {
					console.error(errorResponse);
				}
			});
	}

	private processSelectionResponse(resp: HttpResponse<string>) {
		const location = resp.headers.get('location');
		if (location) {
			// writing the body of the redirect result to the document does not work
			window.location.href = location;
			return;
		}
		// document.write for error page does not work here
		const url = resp.url.replace(/^.*(\/failure\/.*$)/, '$1');
		if (url !== resp.url) {
			void this.router.navigate([url]);
			return;
		}
		window.document.write(resp.body);
		if (document.forms.length > 0) {
			document.forms.item(0).submit();
		} else {
			// not a SAML form, e.g. AccessRequest
			// NOSONAR
			// console.info('[HrdCardsComponent] Do not have a form to submit');
		}
	}
}
