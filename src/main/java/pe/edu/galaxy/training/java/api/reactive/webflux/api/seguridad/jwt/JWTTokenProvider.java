package pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;
import static pe.edu.galaxy.training.java.api.reactive.webflux.api.seguridad.constants.JWTConstants.*;

@Slf4j
@Component
public class JWTTokenProvider {


	private final Base64.Encoder encoder = Base64.getEncoder();

	private String secretKey;

	@PostConstruct
	public void init() {
		log.info("init...");
		this.secretKey = encoder.encodeToString(SALT_KEY.getBytes(StandardCharsets.UTF_8));
	}

	public String getToken(Authentication authentication) {
		
		String authorities = authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority)
				.collect(Collectors.joining(","));
		
		Date validity = new Date((new Date()).getTime() + TOKEN_VALIDITY);

		return Jwts.builder().setSubject(authentication.getName()).claim(AUTHORITIES_KEY, authorities)
				.signWith(SignatureAlgorithm.HS512, secretKey).setExpiration(validity).compact();
	}
	
	

	public Authentication getAuthentication(String token) {
		log.info("token Auth "+token);
		if ((token == null) || !validateToken(token)) {
			throw new BadCredentialsException("Token inválido");
		}

		Claims claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();

		Collection<? extends GrantedAuthority> authorities = Arrays
				.stream(claims.get(AUTHORITIES_KEY).toString().split(",")).map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());

		User principal = new User(claims.getSubject(), "", authorities);
		
		log.info("principal "+principal);
		log.info("token "+token);
		log.info("authorities "+authorities);
		
		return new UsernamePasswordAuthenticationToken(principal, token, authorities);
	}

	private boolean validateToken(String authToken) {
		try {
			Jwts.parser().setSigningKey(secretKey).parseClaimsJws(authToken);
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			log.info("Invalid JWT signature.");
			return false;
		}
	}
}