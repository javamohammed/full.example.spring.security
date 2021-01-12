package tuto.spring.security.auth;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

import tuto.spring.security.security.ApplicationUserRole;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

	@Autowired
	private  PasswordEncoder passwordEncoder;
	
	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		// TODO Auto-generated method stub
		return getApplicationUsers()
				.stream()
				.filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}
	public List<ApplicationUser> getApplicationUsers(){
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
				new ApplicationUser(
						ApplicationUserRole.STUDENT.getGrantedAuthorities(),
						passwordEncoder.encode("123456"),
						"moha",
						true,
						true,
						true,
						true),
				new ApplicationUser(
						ApplicationUserRole.ADMIN.getGrantedAuthorities(),
						passwordEncoder.encode("123456"),
						"admin",
						true,
						true,
						true,
						true),
				new ApplicationUser(
						ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(),
						passwordEncoder.encode("123456"),
						"bilal",
						true,
						true,
						true,
						true)
				);
				
		
		return applicationUsers;
	}

}
