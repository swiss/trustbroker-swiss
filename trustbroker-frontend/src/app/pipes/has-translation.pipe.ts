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
import { Pipe, PipeTransform } from '@angular/core';
import { TranslateService } from '@ngx-translate/core';
import { Observable, of } from 'rxjs';
import { map } from 'rxjs/operators';

@Pipe({
	name: 'hasTranslation',
	standalone: true
})
export class HasTranslationPipe implements PipeTransform {
	constructor(private readonly translationService: TranslateService) {}

	transform(key: string | null): Observable<boolean> {
		if (key == null) {
			return of(false);
		}
		return this.translationService.stream(key).pipe(map(translation => translation !== key));
	}
}
