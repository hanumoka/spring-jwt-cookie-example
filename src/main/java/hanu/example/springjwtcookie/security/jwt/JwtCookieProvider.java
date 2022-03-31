package hanu.example.springjwtcookie.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import hanu.example.springjwtcookie.domain.RefreshToken;
import hanu.example.springjwtcookie.domain.Role;
import hanu.example.springjwtcookie.repo.RefreshTokenRepo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.transaction.Transactional;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtCookieProvider {

    @Value("${jwt.secret-key}")
    private String SECRET_KEY;

    @Value("${jwt.header-name}")
    private String HEADER_NAME;

    @Value("${jwt.access-token-expire-length}")
    private long ACCESS_VALIDITY_IN_MILLISECONDS;

    @Value("${jwt.refresh-token-expire-length}")
    private long REFRESH_VALIDITY_IN_MILLISECONDS;

    private final RefreshTokenRepo refreshTokenRepo;

    @PostConstruct
    protected void init() {
        SECRET_KEY = Base64.getEncoder().encodeToString(SECRET_KEY.getBytes());
    }

    public String createAccessToken(String username, List<String> roles, String issuer, Long refreshTokenId){
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
        return JWT.create()
                .withSubject(username)
                .withExpiresAt(new Date(System.currentTimeMillis() + ACCESS_VALIDITY_IN_MILLISECONDS))
                .withIssuer(issuer)
                .withClaim("roles", roles)
                .withClaim("refresh_token_id", refreshTokenId)
                .sign(algorithm);
    }

    public String createRefreshToken(User user, String issuer){
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
        return JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + REFRESH_VALIDITY_IN_MILLISECONDS))
                .withIssuer(issuer)
                .sign(algorithm);
    }

    public ValidatedUserInfo validateToken(String token) {
        Algorithm algorithm = Algorithm.HMAC256(SECRET_KEY.getBytes());
        JWTVerifier verifier = JWT.require(algorithm).build();
        DecodedJWT decodedJWT = verifier.verify(token);
        String username = decodedJWT.getSubject();
        String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
        return ValidatedUserInfo.builder().username(username).roles(roles).build();
    }

    public String getRefreshTokenIdTokenFromAccessToken(String token){
        DecodedJWT decodedJWT = JWT.decode(token);
        return decodedJWT.getClaim("refresh_token_id").toString();
    }

    /**
     * 액세스 토큰만 쿠키로 저장하고, 리프레쉬 토큰은 DB에 저장한다.
     */
    public HttpServletResponse createCookie(HttpServletResponse response, String token) {
        // TODO : https 적용시 secure 적용 필요
        ResponseCookie cookie = ResponseCookie.from(HEADER_NAME, token)
                .httpOnly(true)
                .sameSite("lax")
                .maxAge(ACCESS_VALIDITY_IN_MILLISECONDS)
                .path("/")
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
        return response;
    }

    public String resolveCookie(HttpServletRequest request) {
        final Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(HEADER_NAME)) {
                return cookie.getValue();
            }
        }
        return null;
    }

    @Transactional
    public RefreshToken saveRefreshToken(String refreshToken) {
        return refreshTokenRepo.save(RefreshToken.builder().token(refreshToken).build());
    }

}

