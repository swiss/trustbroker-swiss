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

import { BucketizeIdpObjectsPipe } from './bucketize-idp-objects.pipe';
import { IdpObject } from '../model/IdpObject';

describe('OrderIdpObjectsPipe', () => {
	const pipe = new BucketizeIdpObjectsPipe();

	it('create an instance', () => {
		expect(pipe).toBeTruthy();
	});

	it('returns undefined on undefined', () => {
		expect(pipe.transform(undefined)).toBeUndefined();
	});

	it('returns [] on []', () => {
		expect(pipe.transform([])).toEqual([]);
	});

	it('orders correctly', () => {
		// given
		const input = [
			{ ...defaultObject, name: 'A', order: undefined },
			{ ...defaultObject, name: 'B', order: 0 },
			{ ...defaultObject, name: 'C', order: -1 },
			{ ...defaultObject, name: 'D', order: 201 },
			{ ...defaultObject, name: 'E', order: 103 },
			{ ...defaultObject, name: 'F', order: 102 },
			{ ...defaultObject, name: 'G', order: 104 },
			{ ...defaultObject, name: 'H', order: 203 },
			{ ...defaultObject, name: 'I', order: 301 },
			{ ...defaultObject, name: 'J', order: undefined }
		];

		// when
		const result = pipe.transform(input);

		// then
		expect(result.map(each => each.map(({ name }) => name))).toEqual([['F', 'E', 'G'], ['D', 'H'], ['I'], ['C', 'A', 'B', 'J']]);
	});

	it('creates no more than the max number of groups', () => {
		// given
		const input = [
			{ ...defaultObject, name: 'A', order: undefined },
			{ ...defaultObject, name: 'B', order: 0 },
			{ ...defaultObject, name: 'C', order: -1 },
			{ ...defaultObject, name: 'D', order: 201 },
			{ ...defaultObject, name: 'E', order: 103 },
			{ ...defaultObject, name: 'F', order: 102 },
			{ ...defaultObject, name: 'G', order: 104 },
			{ ...defaultObject, name: 'H', order: 203 },
			{ ...defaultObject, name: 'I', order: 301 },
			{ ...defaultObject, name: 'J', order: undefined }
		];

		// when
		const result = pipe.transform(input, 3);

		// then
		expect(result.map(each => each.map(({ name }) => name))).toEqual([
			['F', 'E', 'G'],
			['D', 'H'],
			['I', 'C', 'A', 'B', 'J']
		]);
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
