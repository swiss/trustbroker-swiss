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
import { AnyCardHasCategoryPipe } from './any-card-has-category.pipe';
import { IdpObject } from '../model/IdpObject';

describe('AnyCardHasCategoryPipe', () => {
	const pipe = new AnyCardHasCategoryPipe();

	it('create an instance', () => {
		expect(pipe).toBeTruthy();
	});

	it('resolves undefined to false', () => {
		expect(pipe.transform(undefined)).toBe(false);
	});

	it('resolves []] to false', () => {
		expect(pipe.transform({})).toBe(false);
	});

	it('resolves objects without order to false', () => {
		const objects: IdpObject[] = [{ ...defaultObject }, { ...defaultObject }, { ...defaultObject }];
		const idpObjects = { tiles: objects };
		expect(pipe.transform(idpObjects)).toBe(false);
	});

	it('resolves objects with order to true', () => {
		const objects: IdpObject[] = [{ ...defaultObject }, { ...defaultObject, order: 1 }, { ...defaultObject }];
		const idpObjects = { tiles: objects };
		expect(pipe.transform(idpObjects)).toBe(true);
	});

	const defaultObject: IdpObject = {
		urn: 'urn:trustbroker.swiss:idp:SAML-MOCK-1',
		title: 'saml-mock-1',
		image: 'Tile_SAML-Mock.svg',
		name: 'saml-mock-1',
		shortcut: '',
		color: null,
		disabled: undefined,
		order: undefined
	};
});
