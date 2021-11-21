package pe.edu.galaxy.training.java.api.reactive.webflux.service.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.extern.slf4j.Slf4j;
import pe.edu.galaxy.training.java.api.reactive.webflux.document.security.Rol;
import pe.edu.galaxy.training.java.api.reactive.webflux.document.security.Usuario;
import pe.edu.galaxy.training.java.api.reactive.webflux.repostitory.security.UsuarioRespository;
import reactor.core.publisher.Mono;

@Slf4j
@Service
public class UserDetailsServiceImpl implements ReactiveUserDetailsService {
	
	private UsuarioRespository usuarioRespository;
	
	public UserDetailsServiceImpl(UsuarioRespository usuarioRespository) {
		this.usuarioRespository=usuarioRespository;
	}

	@Override
	public Mono<UserDetails> findByUsername(String username) {
		log.info("username "+username);
		Mono<Usuario> usuario= this.usuarioRespository.findByUsuario(username);
		/*usuario.subscribe(
				  value -> System.out.println(value), 
				  error -> error.printStackTrace(), 
				  () -> System.out.println("completed without a value"));*/

		//log.info("usuario "+usuario.block());
		
		return this.usuarioRespository.findByUsuario(username).switchIfEmpty(Mono.defer(() -> {
			return Mono.error(new UsernameNotFoundException("Usuario no existe"));
		})).map(this::toUserDetails);
		 
		
	}

	
	private UserDetails toUserDetails(Usuario usuario) {
		log.info("usuario "+usuario);
		return new User(usuario.getUsuario(), usuario.getClave(), this.getAuthorities(usuario.getRoles()));
	}
	
	public Collection<GrantedAuthority> getAuthorities(List<Rol> roles) {
		//log.info("roles "+roles);
		List<GrantedAuthority> authorities = new ArrayList<>();
		
		  for (Rol rol : roles) { authorities.add(new
		  SimpleGrantedAuthority(rol.getNombre())); }
		 
		return authorities;
	}
}
