package pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.app;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class AppEncode {

	public static void main(String[] args) {
		
		System.err.println(new BCryptPasswordEncoder().encode("xyz"));

	}

}
