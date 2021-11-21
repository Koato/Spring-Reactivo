package pe.edu.galaxy.training.java.api.reactive.webflux.api.gestion.router;

import static org.springframework.web.reactive.function.server.RequestPredicates.DELETE;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RequestPredicates.POST;
import static org.springframework.web.reactive.function.server.RequestPredicates.PUT;
import static pe.edu.galaxy.training.java.api.reactive.webflux.api.constants.Constants.*;
import static pe.edu.galaxy.training.java.api.reactive.webflux.api.constants.HttpResponse.*;
import org.springdoc.core.annotations.RouterOperation;
import org.springdoc.core.annotations.RouterOperations;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import pe.edu.galaxy.training.java.api.reactive.webflux.api.gestion.handler.AlumnoHandler;
import pe.edu.galaxy.training.java.api.reactive.webflux.document.gestion.alumnos.Alumno;

@Configuration
public class AlumnoRouter {
	
	@RouterOperations({ 
		
		@RouterOperation(
				path = API_ROUTE_ALUMNOS,
				method = RequestMethod.GET,
				beanClass = AlumnoHandler.class, 
				beanMethod = "findAll",
				operation = @Operation(	operationId = "findAll",
										responses = {
						                  		@ApiResponse(	responseCode = HTTP_CODE_200,
						                		  				description = HTTP_MSG_200, 
						                		  				content = @Content(schema = @Schema(implementation = Alumno.class))),
						                  		@ApiResponse(	responseCode = HTTP_CODE_204, 
						                  						description = HTTP_MSG_204)
						                  	},
											description = "Listado de todos los Alumnos incluido áreas de especialización",
											summary = "Listado de todos los Alumnos"
										)
		),
		@RouterOperation(
				path = API_ROUTE_ALUMNOS,
				method = RequestMethod.POST,
				beanClass = AlumnoHandler.class, 
				beanMethod = "add",
				operation =@Operation(	operationId = "add",
										responses = {
								                  		@ApiResponse(	responseCode = HTTP_CODE_201,
								                		  				description = HTTP_MSG_201, 
								                		  				content = @Content(schema = @Schema(implementation = Alumno.class))),
								                  		@ApiResponse(	responseCode = HTTP_CODE_400, 
								                  						description = HTTP_MSG_400)
								                  	},
										requestBody = @RequestBody(content = @Content(schema = @Schema(implementation = Alumno.class))),
										description = "Registro de talleres en MongoDB incluido Alumnos y áreas de especialización",
										summary = "Registro de talleres"
									)		 
		)
		}
	)
	
	@Bean
	public RouterFunction<ServerResponse> routeAlumno(AlumnoHandler alumnoHandler) {
		return RouterFunctions
				.route(GET(API_ROUTE_ALUMNOS).and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						alumnoHandler::findAll)
				.andRoute(GET(API_ROUTE_ALUMNOS+"/by-nombres").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						alumnoHandler::findByLikeNombre)
				.andRoute(GET(API_ROUTE_ALUMNOS+"/{id}").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						alumnoHandler::findById)
				.andRoute(GET(API_ROUTE_ALUMNOS+"/codigo/{codigo}")
						.and(RequestPredicates.accept(MediaType.APPLICATION_JSON)), alumnoHandler::findByCodigo)
				.andRoute(POST(API_ROUTE_ALUMNOS).and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						alumnoHandler::add)
				.andRoute(PUT(API_ROUTE_ALUMNOS+"/{id}").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						alumnoHandler::update)
				.andRoute(DELETE(API_ROUTE_ALUMNOS+"/{id}").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						alumnoHandler::delete);
	}
}
