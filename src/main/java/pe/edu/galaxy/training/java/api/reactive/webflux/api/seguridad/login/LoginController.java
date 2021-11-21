package pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.login;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;

import lombok.extern.slf4j.Slf4j;
import pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.dto.UsuarioDTO;
import pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.jwt.JWTReactiveAuthenticationManager;
import pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.jwt.JWTTokenProvider;
import reactor.core.publisher.Mono;
import static pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.constants.JWTConstants.LOGIN_URL;
import static pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.constants.JWTConstants.BEARER;



@Slf4j
@RestController
@RequestMapping(LOGIN_URL)
public class LoginController {

	private final JWTTokenProvider jWTTokenProvider;

	private final JWTReactiveAuthenticationManager authenticationManager;

	public LoginController(JWTTokenProvider jWTTokenProvider, JWTReactiveAuthenticationManager authenticationManager) {
		this.jWTTokenProvider = jWTTokenProvider;
		this.authenticationManager = authenticationManager;
	}

	@PostMapping
	public Mono<ResponseEntity<?>> authorize(@RequestBody UsuarioDTO usuarioDTO) {

		log.info("usuarioDTO " + usuarioDTO);

		Authentication authenticationToken = new UsernamePasswordAuthenticationToken(usuarioDTO.getUsuario(),
				usuarioDTO.getClave());

		Mono<Authentication> authentication = this.authenticationManager.authenticate(authenticationToken);

		authentication.doOnError(throwable -> {
			throw new BadCredentialsException("Usuario y/o clave incorrecta");
		});

		ReactiveSecurityContextHolder.withAuthentication(authenticationToken);

		return authentication.map(auth -> {
			
			String jwt = jWTTokenProvider.getToken(auth);
			
			log.info("jwt " + jwt);
			
			return ResponseEntity.ok()
					.header("Access-Control-Expose-Headers", "Authorization")
					//.header("Access-Control-Allow-Origin", "*")
					.header("Authorization",BEARER+jwt)
				    .build();
		});
		
		// return this.getToken(usuarioDTO);
	}

	/*
	private Mono<ResponseEntity<?>> getToken(UsuarioDTO usuarioDTO) {

		Authentication authenticationToken = new UsernamePasswordAuthenticationToken(usuarioDTO.getUsuario(),
				usuarioDTO.getClave());

		Mono<Authentication> authentication = this.authenticationManager.authenticate(authenticationToken);

		authentication.doOnError(throwable -> {
			throw new BadCredentialsException("Usuario y/o clave incorrecta");
		});

		ReactiveSecurityContextHolder.withAuthentication(authenticationToken);

		return authentication.map(auth -> {
			String jwt = jWTTokenProvider.getToken(auth);
			log.info("jwt " + jwt);
			return ResponseEntity.ok()
				      .header("authorization",jwt)
				      .body(null);
		});

	}*/

}
