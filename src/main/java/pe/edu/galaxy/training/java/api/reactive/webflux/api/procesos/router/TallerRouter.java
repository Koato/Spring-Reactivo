package pe.edu.galaxy.training.java.api.reactive.webflux.api.procesos.router;

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
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import static pe.edu.galaxy.training.java.api.reactive.webflux.api.constants.Constants.*;
import static org.springframework.web.reactive.function.server.RequestPredicates.*;

import pe.edu.galaxy.training.java.api.reactive.webflux.api.procesos.handler.TallerHandler;
import pe.edu.galaxy.training.java.api.reactive.webflux.document.procesos.programacion.Taller;

@Configuration
public class TallerRouter {
	
	@RouterOperations({ 
		@RouterOperation(
				path = API_ROUTE_TALLERES,
				method = RequestMethod.GET,
				beanClass = TallerHandler.class, 
				beanMethod = "findAll",
				operation = @Operation(	operationId = "findAll",
										responses = {
						                  		@ApiResponse(	responseCode = "200",
						                		  				description = "Búsqueda exitosa", 
						                		  				content = @Content(schema = @Schema(implementation = Taller.class))),
						                  		@ApiResponse(	responseCode = "204", 
						                  						description = "Sin contenido")
						                  	},
											description = "Listado de todos los talleres incluido intructor, temas y situación",
											summary = "Listado de todos los talleres"
										)
				),

		@RouterOperation(
				path = API_ROUTE_TALLERES+"/by-nombre",
				method = RequestMethod.GET,
				beanClass = TallerHandler.class, 
				beanMethod = "findByLikeNombre",
				operation =@Operation(	operationId = "findByLikeNombre",
										parameters = {
														@Parameter(	in = ParameterIn.QUERY,
																	name = "nombre", 
																	description = "Nombre del taller",
																	example="Angular 12") 
													},
												responses = {
								                  		@ApiResponse(	responseCode = "200",
								                		  				description = "Búsqueda exitosa", 
								                		  				content = @Content(schema = @Schema(implementation = Taller.class))),
								                  		@ApiResponse(	responseCode = "204", 
								                  						description = "Sin contenido")
								                  	},
												description = "Búsqueda de talleres por nombre",
												summary = "Búsqueda de talleres por nombre"
									)
				), 
		
		@RouterOperation(
				path = API_ROUTE_TALLERES+"/{id}",
				method = RequestMethod.GET,
				beanClass = TallerHandler.class, 
				beanMethod = "findById",
				operation =@Operation(	operationId = "findById",
												parameters = {
														@Parameter(	in = ParameterIn.PATH,
																	name = "id", 
																	description = "Id de taller",
																	example="201efca9-d1a4-443e-982c-60b5691ce6ba" ) },
												description = "Búsqueda de talleres por id",
												summary = "Búsqueda de talleres por id"
											  )
												 
						),
		@RouterOperation(
				path = API_ROUTE_TALLERES+"/codigo/{codigo}",
				method = RequestMethod.GET,
				beanClass = TallerHandler.class, 
				beanMethod = "findByCodigo",
				operation =@Operation(	operationId = "findByCodigo",
												parameters = {
														@Parameter(	in = ParameterIn.PATH,
																	name = "codigo", 
																	description = "Código de taller",
																	example = "1") },
												description = "Búsqueda de talleres por código",
												summary = "Búsqueda de talleres por código"
											  )
												 
						),
		@RouterOperation(
				path = API_ROUTE_TALLERES,
				method = RequestMethod.POST,
				beanClass = TallerHandler.class, 
				beanMethod = "add",
				operation =@Operation(	operationId = "add",
										responses = {
								                  		@ApiResponse(	responseCode = "201",
								                		  				description = "Taller creado", 
								                		  				content = @Content(schema = @Schema(implementation = Taller.class))),
								                  		@ApiResponse(	responseCode = "400", 
								                  						description = "Taller no válido")
								                  	},
										requestBody = @RequestBody(content = @Content(schema = @Schema(implementation = Taller.class),
										examples = @ExampleObject(value = "{\r\n" + 
												"    \"codigo\": 5,\r\n" + 
												"    \"nombre\": \"Net 5\",\r\n" + 
												"    \"duracion\":25,\r\n" + 
												"    \"instructor\": {\r\n" + 
												"        \"codigo\":3,\r\n" + 
												"        \"nombres\": \"Erick\",\r\n" + 
												"        \"apellidos\":\"Arostegui Agunza\",\r\n" + 
												"        \"correo\":\"earostegui@galaxy.edu.pe\",\r\n" + 
												"        \"telefono\": \"+(51) 95050 7877\",\r\n" + 
												"        \"especialidad\":{\r\n" + 
												"           \"codigo\": \"1\",\r\n" + 
												"            \"nombre\": \"Net Developer\"\r\n" + 
												"        }\r\n" + 
												"    },\r\n" + 
												"    \"temas\": [\r\n" + 
												"            {\r\n" + 
												"                \"codigo\": \"1\",\r\n" + 
												"                \"nombre\": \"Introducción genereal\",\r\n" + 
												"                \"descripcion\": \"Nuevas caracteristicas\"\r\n" + 
												"            },\r\n" + 
												"            {\r\n" + 
												"                \"codigo\": \"2\",\r\n" + 
												"                \"nombre\": \"Caso práctico\",\r\n" + 
												"                \"descripcion\": \"Caso pratico con Programacion Concurrente\"\r\n" + 
												"            }\r\n" + 
												"        ],\r\n" + 
												"    \"situacion\":{\r\n" + 
												"        \"codigo\": \"2\",\r\n" + 
												"        \"nombre\": \"Reprogramado\"\r\n" + 
												"    },\r\n" + 
												"    \"estado\":\"1\"\r\n" + 
												"}"))),
										description = "Registro de talleres en MongoDB incluido intructor, temas y situación",
										summary = "Registro de talleres"
									)
												 
						),
		
		@RouterOperation(
				path = API_ROUTE_TALLERES+"/{id}",
				method = RequestMethod.PUT,
				beanClass = TallerHandler.class, 
				beanMethod = "update",
				operation =@Operation(	operationId = "update",
										parameters = {
														@Parameter(	in = ParameterIn.PATH,
															name = "id", 
															description = "id de taller",
															example="201efca9-d1a4-443e-982c-60b5691ce6ba"
														)
														},
										responses = {
						                  		@ApiResponse(	responseCode = "200",
						                		  				description = "Taller actualizado"),
						                  		@ApiResponse(	responseCode = "400", 
		                  										description = "Id de taller no válido"),
						                  		@ApiResponse(	responseCode = "404", 
				          										description = "Taller no encontrado")
										         },
										requestBody = @RequestBody(content = @Content(schema = @Schema(implementation = Taller.class))),
										description = "Actualización de talleres en MongoDB incluido intructor, temas y situación",
										summary = "Registro de talleres"
									)
												 
						),
		@RouterOperation(
				path = API_ROUTE_TALLERES+"/{id}",
				method = RequestMethod.DELETE,
				beanClass = TallerHandler.class, 
				beanMethod = "delete",
				operation =@Operation(	operationId = "delete",
										parameters = {
												@Parameter(	in = ParameterIn.PATH,
													name = "id", 
													description = "id de taller",
													example="201efca9-d1a4-443e-982c-60b5691ce6ba") 
												},
										responses = {
						                  		@ApiResponse(	responseCode = "200",
						                		  				description = "Taller eliminado", 
						                		  				content = @Content(schema = @Schema(implementation = Taller.class))),
						                  		@ApiResponse(	responseCode = "400", 
						                  						description = "Id de taller no válido"),
						                  		@ApiResponse(	responseCode = "404", 
		                  										description = "Taller no encontrado")
						                  	},
										description = "Eliminación de talleres",
										summary = "Eliminación de talleres"
									)			 
						)
	})

	@Bean
	public RouterFunction<ServerResponse> routeTaller(TallerHandler tallerHandler) {
		return RouterFunctions
				.route(GET(API_ROUTE_TALLERES).and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						tallerHandler::findAll)
				.andRoute(GET(API_ROUTE_TALLERES+"/by-nombre").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						tallerHandler::findByLikeNombre)
				.andRoute(GET(API_ROUTE_TALLERES+"/{id}").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						tallerHandler::findById)
				.andRoute(GET(API_ROUTE_TALLERES+"/codigo/{codigo}")
						.and(RequestPredicates.accept(MediaType.APPLICATION_JSON)), tallerHandler::findByCodigo)
				.andRoute(POST(API_ROUTE_TALLERES).and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						tallerHandler::add)
				.andRoute(PUT(API_ROUTE_TALLERES+"/{id}").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						tallerHandler::update)
				.andRoute(DELETE(API_ROUTE_TALLERES+"/{id}").and(RequestPredicates.accept(MediaType.APPLICATION_JSON)),
						tallerHandler::delete);
	}
}
