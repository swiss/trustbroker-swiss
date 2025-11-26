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
import { IdpObject, compareByOrder } from '../model/IdpObject';

/**
 * Filters and bucketizes the given idpObjects by their order number as follows:
 * - items with an order number <= 0 are treated like items without order
 * - items are put into the bucket n where n = order / 100.
 * - inside the buckets, the items are sorted by the order
 * - items with an order number undefined are put in a last bucket
 */
@Pipe({
	name: 'bucketizeIdpObjects',
	standalone: true
})
export class BucketizeIdpObjectsPipe implements PipeTransform {
	transform(objects: IdpObject[] | undefined, maxBuckets?: number): IdpObject[][] {
		if (objects === undefined) {
			return undefined;
		}
		const cardsByCategory: Record<number, IdpObject[]> = objects.reduce((acc, each) => {
			const sanitizedOrder = each.order === undefined || each.order <= 0 ? 999 : each.order;
			const bucket = Math.floor(sanitizedOrder / 100);
			const current = acc[bucket] ?? [];
			current.push(each);
			return {
				...acc,
				[bucket]: current
			};
		}, {});

		const bucketizedCards = Object.keys(cardsByCategory)
			.sort((a, b) => a.localeCompare(b))
			.map(category => cardsByCategory[category].sort(compareByOrder));

		return maxBuckets && bucketizedCards.length > maxBuckets
			? [...bucketizedCards.slice(0, maxBuckets - 1), bucketizedCards.slice(maxBuckets - 1).flat()]
			: bucketizedCards;
	}
}
