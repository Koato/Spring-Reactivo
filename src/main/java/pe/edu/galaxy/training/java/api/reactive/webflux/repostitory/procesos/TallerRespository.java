package pe.edu.galaxy.training.java.api.reactive.webflux.repostitory.procesos;

import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;

import pe.edu.galaxy.training.java.api.reactive.webflux.document.procesos.programacion.Taller;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface TallerRespository extends ReactiveMongoRepository<Taller, String>{
	
	Flux<Taller> findByEstado(String estado);
	
	Flux<Taller> findByNombreLike(String nombre);
	
	Mono<Taller> findByCodigo(Long codigo);

}
