package pe.edu.galaxy.training.java.api.reactive.webflux.document.security;

//import org.springframework.data.mongodb.core.mapping.Field;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Rol {

	//@Field(name = "nombre")
	private String nombre;

}
