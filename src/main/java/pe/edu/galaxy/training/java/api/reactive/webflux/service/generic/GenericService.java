package pe.edu.galaxy.training.java.api.reactive.webflux.service.generic;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

public interface GenericService<T> {
	
	Flux<T> findAll();

	Flux<T> findByLike(T t);
	
	Mono<T> findById(String id);

	Mono<T> findByCodigo(Long codigo);
	
	Mono<T> save(T t);
}
