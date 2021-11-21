package pe.edu.galaxy.training.java.api.reactive.webflux.document.gestion.alumnos;


import org.springframework.data.mongodb.core.mapping.Field;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * La Area representa una linea de especialización (ejem: Java, Net, Angular)
 *
 * @author Aristedes Novoa
 * @version 1.0
 * @since 09 Oct, 2021
 */

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Area {

	@Field(name = "codigo")
	private String codigo;

	@Field(name = "nombre")
	private String nombre;

}
