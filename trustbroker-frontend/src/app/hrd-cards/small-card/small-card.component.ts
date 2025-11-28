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

import { Component, EventEmitter, Input, Output } from '@angular/core';
import { Theme } from '../../model/Theme';
import { ThemeService } from '../../services/theme-service';
import { SafeHtml } from '@angular/platform-browser';

@Component({
	selector: 'app-small-card',
	templateUrl: './small-card.component.html',
	styleUrls: ['./small-card.component.scss'],
	standalone: false
})
export class SmallCardComponent {
	@Input() id: string;
	@Input() showSmallCards: boolean;
	@Input() inputColor: string;
	@Input() inputShortcut: string;
	@Input() cardText: SafeHtml;
	@Input() disabled: boolean;
	@Input() theme: Theme = ThemeService.defaultTheme;

	@Output() readonly cardClick = new EventEmitter<string>();

	selectCard() {
		this.cardClick.emit();
	}

	isDisabled(disabled: boolean) {
		if (disabled) {
			return 1;
		}
		return 0;
	}
}
