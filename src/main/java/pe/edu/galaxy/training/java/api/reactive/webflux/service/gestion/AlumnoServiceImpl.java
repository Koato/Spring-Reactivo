package pe.edu.galaxy.training.java.api.reactive.webflux.service.gestion;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;
import pe.edu.galaxy.training.java.api.reactive.webflux.document.gestion.alumnos.Alumno;
import pe.edu.galaxy.training.java.api.reactive.webflux.repostitory.gestion.AlumnoRespository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@Service
public class AlumnoServiceImpl implements AlumnoService {

	@Autowired
	private AlumnoRespository alumnoRespository;

	@Override
	public Flux<Alumno> findAll() {
		return alumnoRespository.findByEstado("1");
	}

	@Override
	public Flux<Alumno> findByLike(Alumno alumno) {
		return alumnoRespository.findByNombresLike(alumno.getNombres());
	}

	@Override
	public Mono<Alumno> findByCodigo(Long codigo) {
		return alumnoRespository.findByCodigo(codigo);
	}

	@Override
	public Mono<Alumno> findById(String id) {
		return alumnoRespository.findById(id);
	}

	@Override
	public Mono<Alumno> save(Alumno alumno) {
		return alumnoRespository.save(alumno);
	}

}
