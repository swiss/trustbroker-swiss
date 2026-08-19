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
import { ChangeDetectionStrategy, Component, DestroyRef, ElementRef, OnInit, inject } from '@angular/core';
import { MatCheckbox, MatCheckboxChange } from '@angular/material/checkbox';
import { environment } from '../../environments/environment';
import { MatButton } from '@angular/material/button';
import { ObButtonModule, ObDocumentMetaService } from '@oblique/oblique';
import { ReactiveFormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { IdpObject, IdpObjectWithNoticeClaimProviders } from '../model/IdpObject';
import { Observable, delay, of } from 'rxjs';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { TranslatePipe, TranslateService } from '@ngx-translate/core';
import { AsyncPipe, LowerCasePipe } from '@angular/common';
import { HasTranslationPipe } from '../pipes/has-translation.pipe';
import { LanguageService } from '../services/language.service';
import { map } from 'rxjs/operators';
import { HrdSelectionService } from '../services/hrd-selection.service';
import { SafeMarkupStandalonePipe } from '../pipes/safe-markup-standalone.pipe';
import { ClaimsProviderNoticeService } from '../services/claims-provider-notice.service';
import { ValidationService } from '../services/validation-service';

@Component({
	selector: 'claims-provider-notice',
	imports: [MatCheckbox, MatButton, ObButtonModule, ReactiveFormsModule, TranslatePipe, LowerCasePipe, HasTranslationPipe, AsyncPipe, SafeMarkupStandalonePipe],
	templateUrl: './claims-provider-notice.component.html',
	styleUrl: './claims-provider-notice.component.scss',
	standalone: true,
	changeDetection: ChangeDetectionStrategy.OnPush,
	host: {
		'[class]': 'this.idpObject?.name?.toLowerCase()',
		tabindex: '-1'
	}
})
export default class ClaimsProviderNoticeComponent implements OnInit {
	apiBaseUrl: string = environment.apiUrl;
	idpObject: IdpObjectWithNoticeClaimProviders;
	paragraphs$: Observable<string[]>;
	titleKey: string;

	readonly i18nPrefix = `trustbroker.hrd.notice`;

	private readonly router = inject(Router);
	private readonly route = inject(ActivatedRoute);
	private readonly destroyRef = inject(DestroyRef);
	private readonly languageService = inject(LanguageService);
	private readonly translateService = inject(TranslateService);
	private readonly hrdSelectionService = inject(HrdSelectionService);
	private readonly metaService = inject(ObDocumentMetaService);
	private readonly claimsProviderNoticeService = inject(ClaimsProviderNoticeService);
	private readonly validation = inject(ValidationService);
	private readonly hostElement = inject(ElementRef);

	ngOnInit(): void {
		this.idpObject = this.router.lastSuccessfulNavigation()?.extras?.state?.['idpObject'] as IdpObjectWithNoticeClaimProviders;
		this.titleKey = `${this.i18nPrefix}.${this.idpObject.name}.title`.toLowerCase();
		this.metaService.setTitle(this.titleKey);

		of(undefined) // put the focus on the container. A screen reader will start reading right there. Short delay to ensure it's present in the screenreader's cache
			.pipe(delay(200), takeUntilDestroyed(this.destroyRef))
			.subscribe(() => this.hostElement.nativeElement.focus());

		this.paragraphs$ = this.languageService.langChange$.pipe(
			map(() => {
				const paragraphs: string[] = [];
				let index = 1;
				let newParagraph: string | undefined;
				do {
					const key = `${this.i18nPrefix}.${this.idpObject.name}.paragraph${index}`.toLowerCase();
					newParagraph = this.translateService.instant(key);
					newParagraph = newParagraph === key ? undefined : newParagraph;
					if (newParagraph) {
						paragraphs.push(newParagraph);
					}
					index++;
				} while (newParagraph !== undefined);
				return paragraphs;
			})
		);
	}

	updateCookie(event: MatCheckboxChange) {
		if (event.checked) {
			this.claimsProviderNoticeService.setCookie(this.idpObject);
		} else {
			this.claimsProviderNoticeService.deleteCookie(this.idpObject);
		}
	}

	selectIdp(selectedIdpObject: IdpObject): void {
		const authnRequestId = this.validation.getValidParameter(this.route.snapshot.params, 'authnRequestId', ValidationService.ID, '');
		this.hrdSelectionService.selectIdp(authnRequestId, selectedIdpObject);
	}
}
