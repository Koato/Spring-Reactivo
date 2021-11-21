package pe.edu.galaxy.training.java.api.reactive.webflux.service.procesos;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;
import pe.edu.galaxy.training.java.api.reactive.webflux.document.procesos.programacion.Taller;
import pe.edu.galaxy.training.java.api.reactive.webflux.repostitory.procesos.TallerRespository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Slf4j
@Service
public class TallerServiceImpl implements TallerService {

	@Autowired
	private TallerRespository tallerRespository;

	@Override
	public Flux<Taller> findAll() {
		return tallerRespository.findByEstado("1");
	}

	@Override
	public Flux<Taller> findByLike(Taller taller) {
		return tallerRespository.findByNombreLike(taller.getNombre());
	}

	@Override
	public Mono<Taller> findByCodigo(Long codigo) {
		return tallerRespository.findByCodigo(codigo);
	}

	@Override
	public Mono<Taller> findById(String id) {
		return tallerRespository.findById(id);
	}

	@Override
	public Mono<Taller> save(Taller taller) {
		return tallerRespository.save(taller);
	}

}
