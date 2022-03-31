package hanu.example.springjwtcookie.security.jwt;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ValidatedUserInfo{
    private String username;
    String[] roles;
}