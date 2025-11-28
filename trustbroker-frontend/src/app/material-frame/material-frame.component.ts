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

import { Component, Input, ViewChild, ViewEncapsulation } from '@angular/core';
import { Theme } from '../model/Theme';
import { ThemeService } from '../services/theme-service';
import { MatSidenav } from '@angular/material/sidenav';
import { FocusOrigin } from '@angular/cdk/a11y';

@Component({
	selector: 'app-mat-frame',
	templateUrl: './material-frame.component.html',
	styleUrls: ['./material-frame.component.scss'],
	encapsulation: ViewEncapsulation.None,
	standalone: false
})
export class MaterialFrameComponent {
	opened: boolean;
	@Input() showTopNav: boolean;
	@Input() showMyaccount = true;
	@Input() showOnlyLogout: boolean;
	@Input() appName = 'TB';
	@Input() detailedFooter = true;
	@Input() theme: Theme = ThemeService.defaultTheme;

	@ViewChild('sidenav') sidenav: MatSidenav;

	// legalFrameworkAddresses$: Observable<InternationalText>;
	envPrefix = '';

	async toggleHelpPanel(focusOrigin: FocusOrigin): Promise<void> {
		if (this.theme.hasHelpPanel) {
			// on keyboard navigation, automatically focus the first interactive element within the side panel
			this.sidenav.autoFocus = focusOrigin === 'keyboard';
			await this.sidenav.toggle(!this.sidenav.opened, focusOrigin).then();
		}
	}

	async closeHelpPanel(): Promise<void> {
		if (this.theme.hasHelpPanel) {
			await this.sidenav.close().then();
		}
	}
}
