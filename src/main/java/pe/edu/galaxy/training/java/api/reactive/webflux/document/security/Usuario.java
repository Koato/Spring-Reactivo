package pe.edu.galaxy.training.java.api.reactive.webflux.document.security;

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

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@Document(collection = "Usuario")
public class Usuario implements Serializable{

	private static final long serialVersionUID = -5908974002220525773L;

	@Id
	@Builder.Default
    private String id = UUID.randomUUID().toString();
	
	//@Field(name = "codigo")
	//private String codigo;
	
	@Field(name = "usuario")
	private String usuario;

	@Field(name = "clave")
	private String clave;

	@Field(name = "nombres")
	private String nombres;
	
	@Field(name = "roles")
	private List<Rol> roles;
	
	//@Field(name = "estado")
	//private String estado;
	
}
