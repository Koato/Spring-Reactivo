package pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.jwt;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.extern.slf4j.Slf4j;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

@Slf4j
public class JWTReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private ReactiveUserDetailsService reactiveUserDetailsService;
	
	private PasswordEncoder passwordEncoder;

	public JWTReactiveAuthenticationManager(
			ReactiveUserDetailsService reactiveUserDetailsService,
			PasswordEncoder passwordEncoder) {
		this.reactiveUserDetailsService = reactiveUserDetailsService;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Mono<Authentication> authenticate(final Authentication authentication) {
		/*
		 * if (passwordEncoder!=null) { log.info("passwordEncoder is not null"); }else {
		 * log.info("passwordEncoder is  null"); }
		 */
			
		if (authentication.isAuthenticated()) {
			return Mono.just(authentication);
		}
		return Mono.just(authentication)
				.switchIfEmpty(Mono.defer(this::raiseBadCredentials))
				.cast(UsernamePasswordAuthenticationToken.class).flatMap(this::authenticateToken)
				.publishOn(Schedulers.parallel()).onErrorResume(e -> raiseBadCredentials())
				.filter(u -> passwordEncoder.matches((String) authentication.getCredentials(), u.getPassword()))
				.switchIfEmpty(Mono.defer(this::raiseBadCredentials))
				.map(u -> new UsernamePasswordAuthenticationToken(authentication.getPrincipal(),
						authentication.getCredentials(), u.getAuthorities()));
	}

	private <T> Mono<T> raiseBadCredentials() {
		return Mono.error(new BadCredentialsException("Usuario y/o clave incorrecta"));
	}

	private Mono<UserDetails> authenticateToken(final UsernamePasswordAuthenticationToken authenticationToken) {
		
		String username = authenticationToken.getName();

		log.info("Usuario " + username);

		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			log.info("Usuario autenticado " + username);
			return this.reactiveUserDetailsService.findByUsername(username);/*.subscribe(
					  value -> System.out.println("xxx" +value), 
					  error -> error.printStackTrace(), 
					  () -> System.out.println("completed without a valuex"));*/
		}

		return null;
	}
	
	/*
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}*/
	
	
}