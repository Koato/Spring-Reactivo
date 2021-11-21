package pe.edu.galaxy.training.java.api.reactive.webflux.document.procesos.programacion;

//import org.springframework.data.mongodb.core.mapping.Field;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Tema {

	//@Field(name = "codigo")
	private String codigo;

	//@Field(name = "nombre")
	private String nombre;

	//@Field(name = "descripcion")
	private String descripcion;

}
