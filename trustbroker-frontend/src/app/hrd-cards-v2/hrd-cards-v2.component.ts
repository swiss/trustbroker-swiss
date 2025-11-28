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

import { ChangeDetectionStrategy, Component, DestroyRef, TemplateRef, ViewChild, effect, input } from '@angular/core';
import { IdpObject, IdpObjects } from '../model/IdpObject';
import { environment } from '../../environments/environment';
import { ThemeService } from '../services/theme-service';
import { ActivatedRoute, Router } from '@angular/router';
import { ApiService } from '../services/api.service';
import { ValidationService } from '../services/validation-service';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { switchMap } from 'rxjs';
import { IdpObjectService } from '../services/idp-object.service';
import { Dialog } from '@angular/cdk/dialog';
import { Overlay } from '@angular/cdk/overlay';

@Component({
	selector: 'app-hrd-cards-v2',
	templateUrl: './hrd-cards-v2.component.html',
	styleUrl: './hrd-cards-v2.component.scss',
	changeDetection: ChangeDetectionStrategy.OnPush,
	standalone: false
})
export class HrdCardsV2Component {
	baseUrl: string = environment.apiUrl;

	idpObjects = input.required<IdpObjects>();
	theme$ = this.themeService.theme$;

	@ViewChild('disabledDialogContent') disabledDialogContentRef: TemplateRef<Element>;

	constructor(
		private readonly route: ActivatedRoute,
		private readonly router: Router,
		private readonly apiService: ApiService,
		private readonly validation: ValidationService,
		protected readonly themeService: ThemeService,
		private readonly destroyRef: DestroyRef,
		private readonly idpObjectService: IdpObjectService,
		private readonly dialog: Dialog,
		private readonly overlay: Overlay
	) {
		effect(() => {
			if (this.idpObjects().tiles?.length === 1 && !this.idpObjects().tiles[0].disabled) {
				this.onCardClick(this.idpObjects().tiles[0]);
			} else {
				// disabled tiles are also displayed in help
				this.idpObjectService.addIdpObjects(this.idpObjects().tiles);
			}
		});
	}

	public onCardClick(idpObject: IdpObject) {
		this.route.params
			.pipe(
				switchMap(params => this.apiService.selectIdp(this.validation.getValidParameter(params, 'authnRequestId', ValidationService.ID, ''), idpObject.urn)),
				takeUntilDestroyed(this.destroyRef)
			)
			.subscribe({
				next: response => {
					const location = response.headers.get('location');
					if (location) {
						// writing the body of the redirect result to the document does not work
						window.location.href = location;
						return;
					}
					// document.write for error page does not work here
					const url = response.url.replace(/^.*(\/failure\/.*$)/, '$1');
					if (url !== response.url) {
						void this.router.navigate([url]);
						return;
					}
					window.document.write(response.body);
					if (document.forms.length > 0) {
						document.forms.item(0).submit();
					} else {
						// not a SAML form, e.g. AccessRequest
						// NOSONAR
						// console.info('[HrdCardsComponent] Do not have a form to submit');
					}
				},
				error: errorResponse => {
					console.error('an error occured', errorResponse);
				}
			});
	}

	onOpenDialog(idpObject: IdpObject, element: Element, event: Event): void {
		event.stopPropagation(); // avoid the calling the idp represented by the button below
		if (event instanceof KeyboardEvent && event.key !== 'Enter') {
			return;
		}

		element.setAttribute('aria-expanded', 'true');
		const strategy = this.overlay
			.position()
			.flexibleConnectedTo(element)
			.withPositions([
				{ originX: 'start', originY: 'top', overlayX: 'start', overlayY: 'bottom', offsetY: 0 },
				{ originX: 'start', originY: 'bottom', overlayX: 'start', overlayY: 'top', offsetY: 0 }
			]);

		this.dialog.openDialogs.forEach(dialogRef => dialogRef.close());

		const dialogRef = this.dialog.open(this.disabledDialogContentRef, {
			minWidth: element.clientWidth,
			maxWidth: element.clientWidth,
			positionStrategy: strategy,
			data: {
				disabled: idpObject.disabled,
				title: idpObject.title,
				labeledById: element.id
			}
		});

		dialogRef.closed.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => element.setAttribute('aria-expanded', 'false'));
	}
}
