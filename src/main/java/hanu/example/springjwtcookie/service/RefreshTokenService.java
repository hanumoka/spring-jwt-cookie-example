package hanu.example.springjwtcookie.service;

import hanu.example.springjwtcookie.domain.RefreshToken;

public interface RefreshTokenService {
    RefreshToken getRefreshToken(Long id);
}
