package pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.constants;

public class JWTConstants {

	public static final String SALT_KEY 		=	"JpxM4e858rc673syopdZnMFb*ExeqJtUc0HJ_iOxu~jiSYu+yPdPw93OBBjF";
	
	public static final int TOKEN_VALIDITY 		= 	86_400*1_000; // Milisegundos
	
	public static final String AUTHORITIES_KEY 	= 	"auth";
	
	public static final String BEARER 			= 	"Bearer ";
	
	public static final String ROLE_ADMIN 		= 	"ROLE_ADMIN";
	
	public static final String LOGIN_URL 		= 	"/login";
	
	public static final String[] AUTH_WHITELIST = { "/login"/*, "/webjars/**","/favicon.ico",*/ };


}
