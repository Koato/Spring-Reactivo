package pe.edu.galaxy.training.java.api.reactive.webflux.repostitory.gestion;

import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;

import pe.edu.galaxy.training.java.api.reactive.webflux.document.gestion.alumnos.Alumno;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface AlumnoRespository extends ReactiveMongoRepository<Alumno, String>{
	
	Flux<Alumno> findByEstado(String estado);
	
	Flux<Alumno> findByNombresLike(String nombre);
	
	Mono<Alumno> findByCodigo(Long codigo);

}
