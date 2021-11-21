package pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.jwt;

import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

public class JWTHeadersExchangeMatcher implements ServerWebExchangeMatcher {
	
	@Override
	public Mono<MatchResult> matches(final ServerWebExchange exchange) {
		
		Mono<ServerHttpRequest> request = Mono.just(exchange).map(ServerWebExchange::getRequest);
		
		return request.map(ServerHttpRequest::getHeaders).filter(h -> h.containsKey(HttpHeaders.AUTHORIZATION))
				.flatMap(e -> MatchResult.match()).switchIfEmpty(MatchResult.notMatch());
	}
}
