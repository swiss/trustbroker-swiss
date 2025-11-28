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

package swiss.trustbroker.sessioncache.repo;

import java.sql.Timestamp;
import java.util.List;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import swiss.trustbroker.sessioncache.dto.JwkCacheEntity;

@Repository
public interface JwkCacheRepository extends CrudRepository<JwkCacheEntity, String> {

	List<JwkCacheEntity> findAllByOrderByExpirationTimestampAsc();

	@Transactional
	Integer deleteAllInBatchByDeleteTimestampBefore(Timestamp currentTimeStamp);

}
