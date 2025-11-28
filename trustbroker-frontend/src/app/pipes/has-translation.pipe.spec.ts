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

import { HasTranslationPipe } from './has-translation.pipe';
import { instance, mock, when } from 'ts-mockito';
import { TranslateService } from '@ngx-translate/core';
import { of } from 'rxjs';

describe('HasTranslationPipe', () => {
	const translateService = mock(TranslateService);
	const pipe = new HasTranslationPipe(instance(translateService));

	it('create an instance', () => {
		expect(pipe).toBeTruthy();
	});

	it(`returns false if translation does not exist`, done => {
		// given
		const key = 'key';
		when(translateService.stream(key)).thenReturn(of(key));

		// when & then
		pipe.transform(key).subscribe({
			next: result => expect(result).toBe(false),
			complete: done
		});
	});

	it(`returns false if key is null`, done => {
		// when & then
		pipe.transform(null).subscribe({
			next: result => expect(result).toBe(false),
			complete: done
		});
	});

	it(`returns true if translation exists`, done => {
		// given
		const key = 'key';
		when(translateService.stream(key)).thenReturn(of(`existing translation`));

		// when & then
		pipe.transform(key).subscribe({
			next: result => expect(result).toBe(true),
			complete: done
		});
	});
});
