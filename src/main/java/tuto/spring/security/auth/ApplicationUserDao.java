package tuto.spring.security.auth;

import java.util.Optional;

public interface ApplicationUserDao {
	
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username); 

}
