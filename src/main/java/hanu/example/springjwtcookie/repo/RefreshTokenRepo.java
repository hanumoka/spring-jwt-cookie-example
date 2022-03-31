package hanu.example.springjwtcookie.repo;

import hanu.example.springjwtcookie.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepo extends JpaRepository<RefreshToken, Long> {
}
