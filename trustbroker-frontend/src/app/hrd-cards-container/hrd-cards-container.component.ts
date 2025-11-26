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

import { ChangeDetectionStrategy, Component, DestroyRef } from '@angular/core';
import { ActivatedRoute, Params, Router } from '@angular/router';
import { ApiService } from '../services/api.service';
import { ValidationService } from '../services/validation-service';
import { Observable, of, switchMap } from 'rxjs';
import { HttpResponse } from '@angular/common/http';
import { IdpObjects } from '../model/IdpObject';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

@Component({
	selector: 'app-hrd-cards-container',
	templateUrl: './hrd-cards-container.component.html',
	changeDetection: ChangeDetectionStrategy.OnPush,
	standalone: false
})
export class HrdCardsContainerComponent {
	idpObjects$ = this.route.params.pipe(
		switchMap(params => this.processIdpObjects(params)),
		takeUntilDestroyed(this.destroyRef)
	);

	constructor(
		private readonly route: ActivatedRoute,
		private readonly apiService: ApiService,
		private readonly validation: ValidationService,
		private readonly router: Router,
		private readonly destroyRef: DestroyRef
	) {}

	private processIdpObjects(params: Params): Observable<IdpObjects> {
		if (!params['issuer']) {
			// NOSONAR
			// console.debug('[HrdCardsContainerComponent] missing issuer');
			return of({});
		}
		const issuer = this.validation.getValidParameter(params, 'issuer', ValidationService.ID, '');
		const authnRequestId = this.validation.getValidParameter(params, 'authnRequestId', ValidationService.ID, '');
		return this.apiService.getIdpObjects(issuer, authnRequestId).pipe(
			switchMap(response => this.processHttpResponse(response)),
			takeUntilDestroyed(this.destroyRef)
		);
	}

	private processHttpResponse(resp: HttpResponse<string>): Observable<IdpObjects> {
		const url = resp.url.replace(/^.*(\/failure\/.*$)/, '$1');
		if (url !== resp.url) {
			// NOSONAR
			// console.info('[HrdCardsContainerComponent] tiles lookup failed', resp.url);
			void this.router.navigate([url]).then(() => of({}));
			return of({});
		}
		return of(JSON.parse(resp.body) as IdpObjects);
	}
}
