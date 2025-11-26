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

import { Component, EventEmitter, Input, Output, ViewChild, ViewEncapsulation } from '@angular/core';
import { ObEColor, ObPopoverDirective } from '@oblique/oblique';

import { Theme } from '../../model/Theme';
import { ApiService } from '../../services/api.service';
import { LanguageService } from '../../services/language.service';
import { ThemeService } from '../../services/theme-service';
import { FocusOrigin } from '@angular/cdk/a11y';
import { ActivationStart, Router } from '@angular/router';
import { Observable, filter } from 'rxjs';
import { map } from 'rxjs/operators';
import { BreakpointObserver } from '@angular/cdk/layout';
import { toSignal } from '@angular/core/rxjs-interop';
import { HeaderButton } from '../../shared/enums/HeaderButton';

@Component({
	selector: 'app-mat-header',
	templateUrl: './material-header.component.html',
	styleUrls: ['./material-header.component.scss'],
	encapsulation: ViewEncapsulation.None,
	standalone: false
})
export class MaterialHeaderComponent {
	@Input() appName: string;

	@Input() environment: string;

	@Input() theme: Theme = ThemeService.defaultTheme;

	@Output() readonly helpPanel = new EventEmitter<FocusOrigin>();

	@Input({ required: true })
	helpPanelVisible: boolean;

	@ViewChild(ObPopoverDirective) popover: ObPopoverDirective;

	languageDropdownVisible: boolean;

	readonly languages: string[];
	readonly headerButtons: HeaderButton[] = this.apiService.getConfiguration().buttons;

	pageTitle$: Observable<string | undefined>;
	isMobile = toSignal(this.breakpointObserver.observe('(max-width: 600px)').pipe(map(({ matches }) => matches)));

	constructor(
		public readonly languageService: LanguageService,
		private readonly apiService: ApiService,
		private readonly router: Router,
		private readonly breakpointObserver: BreakpointObserver
	) {
		this.languages = this.languageService.availableLanguages;
		this.languageDropdownVisible = false;

		this.pageTitle$ = this.router.events.pipe(
			filter(event => event instanceof ActivationStart),
			map(event => event.snapshot.data['pageTitle'])
		);
	}

	languageSelectionToggle(): void {
		this.languageDropdownVisible = !this.languageDropdownVisible;
	}

	changeLanguage(lang): void {
		this.languageService.changeLanguage(lang);
		if (this.popover !== null) {
			this.popover.close();
		}
		this.languageDropdownVisible = false;
	}

	toggleHelpPanel(event: UIEvent): void {
		const focusOrigin = this.extractFocusOrigin(event);
		if (event instanceof KeyboardEvent && !['Space', 'Enter'].includes(event.code)) {
			return;
		}
		if (this.theme.hasHelpPanel) {
			this.helpPanel.emit(focusOrigin);
		}
	}

	bannerColor() {
		switch (this.environment) {
			case 'DEV':
			case 'REF':
				return ObEColor.DEFAULT;
			default:
				return '#fff';
		}
	}

	bannerBgColor() {
		switch (this.environment) {
			case 'LOCAL':
				return ObEColor.SUCCESS;
			case 'DEV':
				return '#ffd700';
			case 'REF':
				return ObEColor.WARNING;
			case 'TEST':
				return ObEColor.PRIMARY;
			case 'ABN':
				return ObEColor.ERROR;
			default:
				return ObEColor.SUCCESS;
		}
	}

	hideBanner() {
		this.environment = '';
	}

	languageSelectionExpanded(): boolean {
		return this.languageDropdownVisible;
	}

	imageUrl(image: string) {
		return this.apiService.getImageUrl(this.theme, image);
	}

	private extractFocusOrigin(event: UIEvent): FocusOrigin {
		if (event instanceof KeyboardEvent) {
			return 'keyboard';
		}
		if (event instanceof PointerEvent) {
			return event.pointerType === 'touch' ? 'touch' : 'mouse';
		}
		return 'program';
	}
}
