package pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@AllArgsConstructor
@NoArgsConstructor
@Data
public class UsuarioDTO {
	
	private String usuario;
	private String clave;
}
