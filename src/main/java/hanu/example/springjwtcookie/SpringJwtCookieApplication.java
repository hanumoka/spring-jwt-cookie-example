package hanu.example.springjwtcookie;

import hanu.example.springjwtcookie.domain.Role;
import hanu.example.springjwtcookie.domain.User;
import hanu.example.springjwtcookie.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringJwtCookieApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringJwtCookieApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner run(UserService userService){
        return args -> {
            userService.saveRole(new Role(null, "ROLE_USER"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));

            userService.saveUser(new User(null ,"hanumoka1", "hanu1", "1234", new ArrayList<>()));
            userService.saveUser(new User(null ,"hanumoka2", "hanu2", "1234", new ArrayList<>()));
            userService.saveUser(new User(null ,"hanumoka3", "hanu3", "1234", new ArrayList<>()));
            userService.saveUser(new User(null ,"hanumoka4", "hanu4", "1234", new ArrayList<>()));

            userService.addRoleToUser("hanu1", "ROLE_USER");
            userService.addRoleToUser("hanu1", "ROLE_MANAGER");
            userService.addRoleToUser("hanu2", "ROLE_MANAGER");
            userService.addRoleToUser("hanu3", "ROLE_ADMIN");
            userService.addRoleToUser("hanu1", "ROLE_SUPER_ADMIN");
            userService.addRoleToUser("hanu1", "ROLE_ADMIN");
            userService.addRoleToUser("hanu4", "ROLE_USER");
        };
    }

}
