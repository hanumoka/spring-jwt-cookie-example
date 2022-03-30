package hanu.example.springjwtcookie.repo;

import hanu.example.springjwtcookie.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {
    User findByUsername(String username);
}
