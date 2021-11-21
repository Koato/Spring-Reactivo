package pe.edu.galaxy.training.java.api.reactive.webflux;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.reactive.config.CorsRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;

@OpenAPIDefinition(info = @Info(
		title = "Aplicaciones - APIs Reactivas", 
		version = "1.0", 
		description = "Documentación de APIs v1.0",
		contact = @Contact(name ="Galaxy Trainig",email ="contacto@apis.galaxy.edu.pe",url = "https://apis.galaxy.edu.pe" ),
		license = @License(name = "Terminos de uso",url = "https://apis.galaxy.edu.pe/licencias.html")
		)	
)

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}
	
	/*
	 * //@Bean public WebFluxConfigurer corsConfigurer() { return new
	 * WebFluxConfigurer() {
	 * 
	 * @Override public void addCorsMappings(CorsRegistry registry) {
	 * registry.addMapping("/**") .allowCredentials(true)
	 * .allowedHeaders("Authorization", "Cache-Control", "Content-Type")
	 * .allowedMethods("HEAD", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
	 * .allowedOrigins("*"); //.allowedOrigins("http://localhost:3000"); } }; }
	 */

}
