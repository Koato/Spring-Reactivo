package pe.edu.galaxy.training.java.api.reactive.webflux.repostitory.security;

import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import pe.edu.galaxy.training.java.api.reactive.webflux.document.security.Usuario;
import reactor.core.publisher.Mono;

@Repository
public interface UsuarioRespository extends ReactiveMongoRepository<Usuario, String>{

	Mono<Usuario> findByUsuario(String usuario);
	
}
