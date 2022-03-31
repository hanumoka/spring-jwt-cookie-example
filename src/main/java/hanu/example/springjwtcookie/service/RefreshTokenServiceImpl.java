package hanu.example.springjwtcookie.service;

import hanu.example.springjwtcookie.domain.RefreshToken;
import hanu.example.springjwtcookie.repo.RefreshTokenRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepo refreshTokenRepo;

    @Override
    public RefreshToken getRefreshToken(Long id) {
        return refreshTokenRepo.findById(id).orElse(null);
    }
}
