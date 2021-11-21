package pe.edu.galaxy.training.java.api.reactive.webflux.document.procesos.programacion;

import java.io.Serializable;
import java.util.List;
import java.util.UUID;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import pe.edu.galaxy.training.java.api.reactive.webflux.document.gestion.instructores.Instructor;


/**
 * The EmployeeRepository is a simple interface which extend JpaRepository to provide all default methods to your
 * entity/document repository.
 *
 * @author Aristedes Novoa
 * @version 1.0
 * @since 25 Sep, 2021
 */

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
@Document(collection = "taller")
public class Taller implements Serializable {

	private static final long serialVersionUID = 1L;
	
	@Id
	@Builder.Default
    private String id = UUID.randomUUID().toString();
	
	@Field(name = "codigo")
	private Long codigo;

	@Field(name = "nombre")
	private String nombre;
	
	@Field(name = "duracion")
	private Double duracion;
	
	@Field(name = "instructor")	
	private Instructor instructor;
	
	@Field(name = "temas")	
	private List<Tema> temas;
	
	@Field(name = "situcion")	
	private Situacion situacion;

	@Field(name = "estado")
	private String estado;

}
