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

import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import swiss.trustbroker.sessioncache.dto.StateEntity;

@Repository
public interface StateCacheRepository extends CrudRepository<StateEntity, String> {

	// Align primary key finder to have a List API
	default List<StateEntity> findByIdAsList(String id) {
		return findById(id).map(List::of).orElseGet(List::of);
	}

	// RP InResponseTo correlation
	List<StateEntity> findBySpSessionId(String spId);

	// spring-authorization-server SSO correlation (OIDC login)
	List<StateEntity> findBySsoSessionId(String spId);

	// spring-authorization-server JSESSIONID correlation (OIDC logout)
	List<StateEntity> findByOidcSessionId(String spId);

	// reaping - transaction is at this fine-grained level to minimize impact on other actions
	// JQL because the standard repository query uses EntityResultInitializer downloading entities from the DB
	@Transactional
	@Modifying
	@Query("DELETE FROM StateEntity se WHERE se.expirationTimestamp < :currentTimeStamp")
	Integer deleteAllInBatchByExpirationTimestampBefore(@Param("currentTimeStamp") Timestamp currentTimeStamp);

}
