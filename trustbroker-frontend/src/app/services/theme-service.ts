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

import { Observable, Observer, ReplaySubject } from 'rxjs';
import { CookieConfiguration } from '../model/CookieConfiguration';
import { Theme } from '../model/Theme';
import { GuiFeature } from '../shared/enums/GuiFeature';
import { HeaderButton } from '../shared/enums/HeaderButton';
import { ApiService } from './api.service';
import { CookieService } from './cookie-service';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { DestroyRef, Injectable } from '@angular/core';

@Injectable({ providedIn: 'root' })
export class ThemeService {
	public static readonly defaultTheme = new Theme('xtb-default', true, true, false, false, true);

	public readonly theme$: Observable<Theme>;

	private static readonly variantSeparator = '-';

	private themeCookie: CookieConfiguration;

	private buttons: HeaderButton[];

	private features: GuiFeature[];

	private defaultCookieParameters: boolean;
	private readonly themeChangedSubject = new ReplaySubject<Theme>();

	constructor(
		private readonly cookieService: CookieService,
		private readonly apiService: ApiService,
		private readonly destroyRef: DestroyRef
	) {
		this.themeCookie = new CookieConfiguration();
		// Defaults until we get the information from the server.
		// Allow all themes to avoid initially showing a wrong default theme. This would still happen if the cookie has a different name.
		this.themeCookie.name = 'THEME';
		this.themeCookie.defaultValue = ThemeService.toCookie(ThemeService.defaultTheme.name);
		this.themeCookie.values = ['default', 'light', 'dark'];
		this.buttons = [HeaderButton.HELP_PANEL, HeaderButton.LANGUAGE_SHORT];
		this.features = [GuiFeature.HEADER, GuiFeature.FOOTER];
		this.defaultCookieParameters = true;
		this.loadConfig();
		this.theme$ = this.themeChangedSubject.asObservable();
	}

	public subscribe(observer: Partial<Observer<Theme>>) {
		this.themeChangedSubject.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(observer);
	}

	public getTheme(): Theme {
		return this.themeNamed(this.getThemeName());
	}

	public toggleTheme() {
		// NOSONAR
		// console.info('[ThemeService]: toggleTheme');
		const theme = this.getTheme();
		if (!theme.hasThemeSelector) {
			return;
		}
		const newTheme = this.switchVariant(theme.name);
		this.updateTheme(newTheme);
	}

	// light -> xtb-light
	private static fromCookie(theme: string): string {
		return ThemeService.isThemeSet(theme) ? `xtb-${theme}` : null;
	}

	// xtb-light -> light
	private static toCookie(theme: string): string {
		return ThemeService.isThemeSet(theme) ? theme?.split(ThemeService.variantSeparator)[1] : null;
	}

	private static isThemeSet(theme: string): boolean {
		return theme !== null && theme !== '';
	}

	private themeNamed(theme: string): Theme {
		// The full range of options that are configurable in principle is not yet supported (button ordering, button types, features)
		const hasHelpPanel = this.buttons.includes(HeaderButton.HELP_PANEL);
		const hasHeader = this.features.includes(GuiFeature.HEADER);
		const hasFooter = this.features.includes(GuiFeature.FOOTER);
		const hasBackdrop = this.features.includes(GuiFeature.BACKDROP);
		const themeSelectorIndex = this.buttons.indexOf(HeaderButton.THEME);

		// NOSONAR
		// console.debug('[ThemeService] Theme', theme, 'helpPanel:', hasHelpPanel, 'backdrop:', hasBackdrop, 'variants:', hasVariants, 'helpTabindex:', helpTabindex);
		return new Theme(theme, hasHeader, hasFooter, hasBackdrop, themeSelectorIndex >= 0, hasHelpPanel);
	}

	private loadConfig() {
		const configuration = this.apiService.getConfiguration();
		const themeCookie: CookieConfiguration = configuration.themeCookie;
		if (themeCookie?.name == null || themeCookie.values == null) {
			// NOSONAR
			// console.debug('[ThemeService] Keeping default theme cookie', this.themeCookie.name, 'values:', this.themeCookie.values);
			return;
		}
		this.themeCookie = themeCookie;
		this.features = configuration.features;
		if (this.features == null) {
			this.features = [];
		}
		this.buttons = configuration.buttons;
		if (this.buttons == null) {
			this.buttons = [];
		}
		this.defaultCookieParameters = false;
		// NOSONAR
		// console.debug('[ThemeService] Server sent theme cookie parameters', this.themeCookie.name, 'values:', this.themeCookie.values);
		this.publish(this.getTheme());
	}

	private publish(theme: Theme): void {
		// NOSONAR
		// console.debug('[ThemeService] Publishing theme change to', theme.name);
		this.themeChangedSubject.next(theme);
	}

	// 1. prio local storage (synchronize with other applications)
	// 2. prio language cookie
	// 3. prio user's preferred variant
	// 4. fallback to default from config
	private getThemeName(): string {
		const themeFromCookie = this.getThemeFromCookie();
		// NOSONAR
		// console.debug('[ThemeService] Theme from cookie:', themeFromCookie);
		if (this.isThemeValid(themeFromCookie)) {
			const converted = ThemeService.fromCookie(themeFromCookie);
			// NOSONAR
			// console.debug('[ThemeService] Using theme from cookie:', themeFromCookie, converted);
			if (ThemeService.isThemeSet(converted)) {
				return converted;
			}
		}
		if (ThemeService.defaultTheme.hasThemeSelector) {
			const themeFromWindow = this.preferredThemeVariant();
			if (ThemeService.isThemeSet(themeFromWindow)) {
				// NOSONAR
				// console.debug('[ThemeService] Using preferred theme variant from window:', themeFromWindow);
				return themeFromWindow;
			}
		}
		// NOSONAR
		// console.debug('[ThemeService] Using default theme:', ThemeService.defaultTheme);
		return ThemeService.defaultTheme.name;
	}

	private getThemeFromCookie(): string {
		const theme = this.cookieService.get(this.themeCookie.name); // NOSONAR typescript:S1488
		// NOSONAR
		// console.debug('[ThemeService] Theme from cookie', this.themeCookie.name, '=', theme);
		return theme;
	}

	private isThemeValid(theme: string): boolean {
		if (!ThemeService.isThemeSet(theme)) {
			// NOSONAR
			// console.debug('[ThemeService] Missing theme', theme);
			return false;
		}
		for (const value of this.themeCookie.values) {
			if (value === theme) {
				// NOSONAR
				// console.debug('[ThemeService] Received valid theme', theme);
				return true;
			}
		}
		// NOSONAR
		// console.info('[ThemeService] Ignoring invalid theme from cookie:', theme, 'not in', this.themeCookie.values);
		return false;
	}

	private preferredThemeVariant() {
		for (const key of this.themeCookie.values) {
			const preferTheme = window.matchMedia(`(prefers-color-scheme: ${key})`);
			if (preferTheme.matches) {
				const themeFromWindow = ThemeService.fromCookie(key);
				if (themeFromWindow) {
					return themeFromWindow;
				}
			}
		}
		return null;
	}

	private switchVariant(theme: string): Theme {
		if (theme === null || this.themeCookie.values.length < 2) {
			// NOSONAR
			// console.info('[ThemeService] Missing theme, using', ThemeService.defaultTheme);
			return ThemeService.defaultTheme;
		}
		const [base, currentVariant] = theme.split(ThemeService.variantSeparator);
		for (let index = 0; index < this.themeCookie.values.length; ++index) {
			if (this.themeCookie.values[index] === currentVariant) {
				// switch to next available variant
				const newVariant = this.themeCookie.values[(index + 1) % this.themeCookie.values.length];
				// NOSONAR
				// console.debug('[ThemeService] Switched theme', theme, 'to', `${base}-${newVariant}`);
				return this.themeNamed(`${base}-${newVariant}`);
			}
		}
		// NOSONAR
		// console.info('[ThemeService] No matching variant for', theme, ', using', ThemeService.defaultTheme);
		return ThemeService.defaultTheme;
	}

	private updateTheme(newTheme: Theme) {
		this.updateCookie(newTheme.name);
		this.publish(newTheme);
	}

	private updateCookie(theme: string) {
		if (this.defaultCookieParameters) {
			// NOSONAR
			// console.debug('[ThemeService] Skip setting cookie based on default parameters');
			return;
		}
		theme = ThemeService.toCookie(theme);
		// NOSONAR
		// console.debug('[ThemeService] Setting theme cookie:', this.themeCookie.name, '=', theme, 'on path', this.themeCookie.path, 'and domain', this.themeCookie.domain);
		this.cookieService.set(this.themeCookie, theme);
	}
}
