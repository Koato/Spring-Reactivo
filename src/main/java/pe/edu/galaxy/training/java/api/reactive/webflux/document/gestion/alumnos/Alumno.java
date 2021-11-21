package pe.edu.galaxy.training.java.api.reactive.webflux.document.gestion.alumnos;

import java.util.List;
import java.util.UUID;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "Alumno")
public class Alumno {
	
	@Id
	@Builder.Default
    private String id = UUID.randomUUID().toString();
	
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
	
	@Field(name = "areas")
	private List<Area> areas;
	
	@Field(name = "estado")
	private String estado;
}
