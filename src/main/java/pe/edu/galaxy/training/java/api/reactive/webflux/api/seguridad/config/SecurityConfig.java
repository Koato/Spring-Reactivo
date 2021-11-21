package pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.jwt.JWTHeadersExchangeMatcher;
import pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.jwt.JWTReactiveAuthenticationManager;
import pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.jwt.JWTTokenProvider;
import pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.token.TokenAuthenticationConverter;
import static pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.constants.JWTConstants.*;

import java.util.Arrays;

import static java.util.Arrays.asList;

@Configuration
@EnableReactiveMethodSecurity
@EnableWebFluxSecurity

class SecurityConfig {

	private final ReactiveUserDetailsService reactiveUserDetailsService;

	private final JWTTokenProvider jWTtokenProvider;
	private PasswordEncoder passwordEncoder;

	public SecurityConfig(ReactiveUserDetailsService reactiveUserDetailsService, JWTTokenProvider jWTtokenProvider,
			PasswordEncoder passwordEncoder) {
		this.reactiveUserDetailsService = reactiveUserDetailsService;
		this.jWTtokenProvider = jWTtokenProvider;
		this.passwordEncoder = passwordEncoder;
	}

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

		http.httpBasic().disable().formLogin().disable().csrf().disable().logout().disable();
		
		http.cors().configurationSource(urlBasedCorsConfigurationSource());
		
		http.addFilterAt(webFilter(), SecurityWebFiltersOrder.AUTHORIZATION).authorizeExchange()
				.pathMatchers(HttpMethod.POST, LOGIN_URL).permitAll().pathMatchers(AUTH_WHITELIST).permitAll()
				.anyExchange().authenticated();

		return http.build();
	}

	@Bean
	public AuthenticationWebFilter webFilter() {
		AuthenticationWebFilter authenticationWebFilter = new AuthenticationWebFilter(
				repositoryReactiveAuthenticationManager());

		authenticationWebFilter.setServerAuthenticationConverter(new TokenAuthenticationConverter(jWTtokenProvider));

		authenticationWebFilter.setRequiresAuthenticationMatcher(new JWTHeadersExchangeMatcher());

		authenticationWebFilter.setSecurityContextRepository(new WebSessionServerSecurityContextRepository());

		return authenticationWebFilter;
	}

	@Bean
	public JWTReactiveAuthenticationManager repositoryReactiveAuthenticationManager() {
		JWTReactiveAuthenticationManager repositoryReactiveAuthenticationManager = new JWTReactiveAuthenticationManager(
				reactiveUserDetailsService, passwordEncoder);
		return repositoryReactiveAuthenticationManager;
	}
	

	private UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource() {
		CorsConfiguration corsConfiguration = new CorsConfiguration();
		corsConfiguration.applyPermitDefaultValues();
		// corsConfiguration.setAllowCredentials(true);
		corsConfiguration.setAllowedHeaders(Arrays.asList("*"));
		corsConfiguration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE"/*, "PATCH", "OPTIONS"*/));
		//corsConfiguration.setAllowedMethods(Arrays.asList("*"));
		corsConfiguration.setAllowedOrigins(Arrays.asList("*"));
		
		UrlBasedCorsConfigurationSource ccs = new UrlBasedCorsConfigurationSource();
		
		ccs.registerCorsConfiguration("/**", corsConfiguration);
		return ccs;
	}
	
}
