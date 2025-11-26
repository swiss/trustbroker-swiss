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
import { IdpObject, compareByOrder } from './IdpObject';

describe('compareByOrder', () => {
	it('compares undefined correctly', () => {
		// given
		const a = { ...defaultObject, order: 101, name: 'A' };
		const b = { ...defaultObject, order: undefined, name: 'B' };

		// when & then
		expect(compareByOrder(a, b)).toEqual(-1);
		expect(compareByOrder(b, a)).toEqual(1);
		expect([a, b].sort(compareByOrder).map(({ name }) => name)).toEqual(['A', 'B']);
		expect([b, a].sort(compareByOrder).map(({ name }) => name)).toEqual(['A', 'B']);
	});

	it('compares undefined correctly', () => {
		// given
		const a = { ...defaultObject, order: 101, name: 'A' };
		const b = { ...defaultObject, order: 103, name: 'B' };

		// when & then
		expect(compareByOrder(a, b)).toEqual(-2);
		expect(compareByOrder(b, a)).toEqual(2);
		expect([a, b].sort(compareByOrder).map(({ name }) => name)).toEqual(['A', 'B']);
		expect([b, a].sort(compareByOrder).map(({ name }) => name)).toEqual(['A', 'B']);
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
