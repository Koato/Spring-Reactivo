package pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.token;

import java.util.Objects;
import java.util.function.Function;
import java.util.function.Predicate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import lombok.extern.slf4j.Slf4j;
import pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.jwt.JWTTokenProvider;
import pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.util.SecurityUtil;
import reactor.core.publisher.Mono;
import static pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.constants.JWTConstants.*;

@Slf4j
public class TokenAuthenticationConverter implements ServerAuthenticationConverter {
	
	//private static final Predicate<String> length = authValue -> authValue.length() > BEARER.length();
	private static final Function<String, String> value = authValue -> authValue.substring(BEARER.length(), authValue.length());
	private final JWTTokenProvider jWTTokenProvider;

	public TokenAuthenticationConverter(JWTTokenProvider jWTTokenProvider) {
		this.jWTTokenProvider = jWTTokenProvider;
	}

	@Override
	public Mono<Authentication> convert(ServerWebExchange serverWebExchange) {
		
		return  Mono.justOrEmpty(serverWebExchange)
						.map(SecurityUtil::getTokenFromRequest)
						//.filter(Objects::nonNull)
						//.filter(length)
						.map(value)
						//.filter(token -> !(token!=""))
						.map(jWTTokenProvider::getAuthentication)
						.filter(Objects::nonNull);
	}

}