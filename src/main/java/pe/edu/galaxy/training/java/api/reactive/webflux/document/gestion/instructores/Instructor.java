package pe.edu.galaxy.training.java.api.reactive.webflux.document.gestion.instructores;

import org.springframework.data.mongodb.core.mapping.Field;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Instructor {

	@Field(name = "codigo")
	private String codigo;

	@Field(name = "nombres")
	private String nombres;

	@Field(name = "apellidos")
	private String apellidos;

	@Field(name = "correo")
	private String correo;

	@Field(name = "telefono")
	private String telefono;
	
	@Field(name = "especialidad")
	private Especialidad especialidad;

}
