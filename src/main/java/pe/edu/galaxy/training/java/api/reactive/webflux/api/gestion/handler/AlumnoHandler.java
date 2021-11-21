package pe.edu.galaxy.training.java.api.reactive.webflux.api.gestion.handler;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import static org.springframework.web.reactive.function.server.ServerResponse.ok;
import static org.springframework.web.reactive.function.server.ServerResponse.status;
import org.springframework.beans.factory.annotation.Autowired;
import static org.springframework.web.reactive.function.BodyInserters.fromPublisher;

import pe.edu.galaxy.training.java.api.reactive.webflux.document.gestion.alumnos.Alumno;
import pe.edu.galaxy.training.java.api.reactive.webflux.service.gestion.AlumnoService;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@Component
@Tag(name = "Alumno Resource", description = "API de gestión de alumnos")
public class AlumnoHandler {

	@Autowired
	private AlumnoService alumnoService;
	
	@Autowired
	private JsonMapper jsonMapper;

	public Mono<ServerResponse> findAll(ServerRequest request) {

		Flux<Alumno> alumnos = alumnoService.findAll();
		return ok().contentType(MediaType.APPLICATION_JSON).body(alumnos, Alumno.class);
	}

	public Mono<ServerResponse> findByLikeNombre(ServerRequest request) {
		Flux<Alumno> alumnos = alumnoService.findByLike(Alumno.builder().nombres(request.queryParam("nombre").get()).build());
		System.out.println(alumnos);
		return ok().body(alumnos, Alumno.class);

	}

	public Mono<ServerResponse> findById(ServerRequest request) {
		return ok().body(alumnoService.findById(request.pathVariable("id")), Alumno.class);
	}

	public Mono<ServerResponse> findByCodigo(ServerRequest request) {
		return ok().body(alumnoService.findByCodigo(Long.valueOf(request.pathVariable("codigo"))), Alumno.class);
	}

	public Mono<ServerResponse> add(ServerRequest request) {
		Mono<Alumno> alumno = request.bodyToMono(Alumno.class);
		return status(HttpStatus.CREATED).body(fromPublisher(alumno.flatMap(alumnoService::save), Alumno.class));
	}

	public Mono<ServerResponse> update(ServerRequest request) {

		String id = request.pathVariable("id");
		Mono<Alumno> alumnoMono = request.bodyToMono(Alumno.class);

		return alumnoService.findById(id).flatMap(alumno1 -> alumnoMono.flatMap(alumno2 -> {
			alumno2.setId(id);
			Mono<Alumno> updatedAlumno = alumnoService.save(this.getAlumno(alumno2));

			return ok().body(updatedAlumno, Alumno.class);
		}));
	}

	public Mono<ServerResponse> delete(ServerRequest request) {

		String id = request.pathVariable("id");
		return alumnoService.findById(id).flatMap(alumno -> {
			alumno.setEstado("0");
			Mono<Alumno> updatedAlumno = alumnoService.save(alumno);
			return ok().body(updatedAlumno, Alumno.class);
		});
	}


	// Mapper
	
	private Alumno getAlumno(Alumno alumno) {
		return jsonMapper.convertValue(alumno, Alumno.class);
	}
}
