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

import { ChangeDetectionStrategy, Component, HostBinding, computed, input, signal } from '@angular/core';
import { environment } from '../../environments/environment';
import { BannerConfig } from '../model/IdpObject';
import { TranslateService } from '@ngx-translate/core';
import { map } from 'rxjs/operators';
import { toObservable } from '@angular/core/rxjs-interop';
import { LanguageService } from '../services/language.service';
import { Observable, combineLatest, switchMap } from 'rxjs';
import { Theme } from '../model/Theme';

@Component({
	selector: 'app-hrd-cards-banner',
	templateUrl: './hrd-banner.component.html',
	styleUrl: './hrd-banner.component.scss',
	changeDetection: ChangeDetectionStrategy.OnPush,
	standalone: false
})
export class HrdBannerComponent {
	baseUrl: string = environment.apiUrl;
	readonly i18nPrefix = `trustbroker.hrd.cards.banner`;

	config = input.required<BannerConfig>();
	theme = input.required<Theme>();

	translatedTitle$ = this.streamTranslation(name => `${this.i18nPrefix}.${name}.title`);
	translatedSubtitle$ = this.streamTranslation(name => `${this.i18nPrefix}.${name}.subtitle`);
	paragraphs$ = combineLatest([toObservable(this.config), this.languageService.langChange$]).pipe(
		map(([{ name }]) => {
			const paragraphs = [];
			let index = 1;
			let newParagraph: string;
			do {
				const key = `${this.i18nPrefix}.${name}.paragraph${index}.text`;
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

	showParagraphsExpanded = computed(() => !this.config().collapseParagraphs || this.expandedParagraphs());

	private readonly expandedParagraphs = signal(false);

	constructor(
		private readonly translateService: TranslateService,
		private readonly languageService: LanguageService
	) {}

	@HostBinding('class')
	get customClass(): string {
		return this.config().name;
	}

	expandParagraphs(expand: boolean): void {
		this.expandedParagraphs.set(expand);
	}

	streamTranslation(keyFn: (bannerName: string) => string): Observable<string> {
		return toObservable(this.config).pipe(
			switchMap(({ name }) => {
				const key = keyFn(name);
				return this.translateService.stream(key).pipe(map<string, string>(translation => (translation === key ? undefined : translation)));
			})
		);
	}
}
