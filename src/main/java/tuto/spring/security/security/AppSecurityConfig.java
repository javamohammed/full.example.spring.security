package tuto.spring.security.security;

import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import tuto.spring.security.auth.ApplicationUserService;
import tuto.spring.security.jwt.JwtConfig;
import tuto.spring.security.jwt.JwtTokenVerifier;
import tuto.spring.security.jwt.JwtUsernameAndPasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AppSecurityConfig  extends WebSecurityConfigurerAdapter{

	private  PasswordEncoder passwordEncoder;
	private ApplicationUserService applicationUserService;
	private final SecretKey secretKey;
    private final JwtConfig jwtConfig;
    
    @Autowired
    public AppSecurityConfig(PasswordEncoder passwordEncoder,  ApplicationUserService applicationUserService, SecretKey secretKey, JwtConfig jwtConfig) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }
	

	
	protected void configureBackup(HttpSecurity http) throws Exception {
		
		http
			//.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			//.and()
			.csrf().disable()
			.authorizeRequests()
			.antMatchers("/", "index", "/css/**", "/js/**").permitAll()
			.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
			/*
			.antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
			.antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
			.antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationUserPermission.STUDENT_WRITE.getPermission())
			.antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
			*/
			.anyRequest()
			.authenticated()
			.and()
			//.httpBasic()
			.formLogin()
				.loginPage("/login").permitAll()
				.defaultSuccessUrl("/courses", true)
				.passwordParameter("password")//you can charge these names but you should change its also in the login.html
				.usernameParameter("username")
			.and()
			.rememberMe()
				.tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
				.key("somthingVeryScured").userDetailsService(applicationUserService)
				.rememberMeParameter("remember-me")
			.and()
			.logout()
				.logoutUrl("/logout")
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // if you disabled the csrf you can use the GET Method if not its the Method Post used by default
				.clearAuthentication(true)
				.invalidateHttpSession(true)
				.deleteCookies("JSESSIONID", "remember-me")
				.logoutSuccessUrl("/");
	}
	
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		//JWT authentication
		http
			.csrf().disable()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), secretKey, jwtConfig))
			.addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
			.authorizeRequests()
			.antMatchers("/", "index", "/css/**", "/js/**").permitAll()
			.antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
			.anyRequest()
			.authenticated();
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// TODO Auto-generated method stub
		auth.authenticationProvider(daoAuthenticationProvider());
	}
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		
		return provider;
	}
	
	/*
	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails user = User
							.builder()
							.username("moha")
							.password(passwordEncoder.encode("123456"))
							//.roles(ApplicationUserRole.STUDENT.name())
							.authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
							.build();
		UserDetails admin = User
				.builder()
				.username("admin")
				.password(passwordEncoder.encode("123456"))
				//.roles(ApplicationUserRole.ADMIN.name())
				.authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
				.build();
		UserDetails adminTrainee = User
				.builder()
				.username("bilal")
				.password(passwordEncoder.encode("123456"))
				//.roles(ApplicationUserRole.ADMIN.name())
				.authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
				.build();
		return new InMemoryUserDetailsManager(
					admin,
					adminTrainee,
					user
		);
	}
	*/
	
}
