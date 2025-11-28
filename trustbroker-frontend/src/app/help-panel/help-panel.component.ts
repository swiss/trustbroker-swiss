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

import { Component, EventEmitter, Input, OnInit, Output, ViewEncapsulation } from '@angular/core';

import { IdpObject, compareByOrder } from '../model/IdpObject';
import { Theme } from '../model/Theme';
import { IdpObjectService } from '../services/idp-object.service';
import { ThemeService } from '../services/theme-service';
import { map } from 'rxjs/operators';
import { Observable } from 'rxjs';

@Component({
	selector: 'app-help-panel',
	templateUrl: './help-panel.component.html',
	styleUrls: ['./help-panel.component.scss'],
	encapsulation: ViewEncapsulation.None,
	standalone: false
})
export class HelpPanelComponent implements OnInit {
	sortedIdpObjects$: Observable<IdpObject[]>;

	@Input() theme: Theme = ThemeService.defaultTheme;

	@Output() readonly helpPanel = new EventEmitter<unknown>();

	constructor(public readonly idpObjectService: IdpObjectService) {}

	// note: [tabindex] on mat-expansion-panel-header does not work:
	// https://github.com/angular/components/issues/22521
	// else we would set tabindex on the close button and the headers to theme.helpTabindex + 1

	ngOnInit(): void {
		this.sortedIdpObjects$ = this.idpObjectService.getIdpObjects().pipe(map(objects => [...objects].sort(compareByOrder)));
	}

	closeHelpPanel(): void {
		this.helpPanel.emit();
	}
}
