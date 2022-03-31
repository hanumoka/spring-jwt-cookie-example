package hanu.example.springjwtcookie.security.filter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.fasterxml.jackson.databind.ObjectMapper;
import hanu.example.springjwtcookie.domain.RefreshToken;
import hanu.example.springjwtcookie.domain.Role;
import hanu.example.springjwtcookie.domain.User;
import hanu.example.springjwtcookie.security.jwt.JwtCookieProvider;
import hanu.example.springjwtcookie.security.jwt.ValidatedUserInfo;
import hanu.example.springjwtcookie.service.RefreshTokenService;
import hanu.example.springjwtcookie.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAuthorizationFilter extends OncePerRequestFilter {

    private final JwtCookieProvider jwtCookieProvider;
    private final RefreshTokenService refreshTokenService;
    private final UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 요청으보부터 JWT Token을 검사하는 필터
        if (request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) {
            // 로그인 요청에서는 아무것도 안함
            filterChain.doFilter(request, response);
        } else {
            String refreshTokenId = null;
            String accessToken = null;
            try {
                accessToken = jwtCookieProvider.resolveCookie(request);
                ValidatedUserInfo validatedUserInfo = jwtCookieProvider.validateToken(accessToken);

                String username = validatedUserInfo.getUsername();
                String[] roles = validatedUserInfo.getRoles();

                Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                stream(roles).forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                filterChain.doFilter(request, response);
            } catch (TokenExpiredException tokenExpiredException) {
                log.error("Error logging in: {}", tokenExpiredException.getMessage());
                // 액세스토큰 만료시 엑세스 토큰에서 리프레시 토큰 id를 가져온다.
                refreshTokenId = jwtCookieProvider.getRefreshTokenIdTokenFromAccessToken(accessToken);
                log.info("refreshTokenId : {}", refreshTokenId);
            } catch (JWTVerificationException jwtVerificationException) {
                log.error("Error logging in: {}", jwtVerificationException.getMessage());
                response.setHeader("error", jwtVerificationException.getMessage());
                response.setStatus(UNAUTHORIZED.value());
                Map<String, String> error = new HashMap<>();
                error.put("error_message", jwtVerificationException.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);
            }

            if (StringUtils.isNotBlank(refreshTokenId)) {
                // 리프레시토큰으로 액세토큰 재발급 시도

                // 1, 리프레시토큰을 DB에서 조회
                RefreshToken refreshToken = refreshTokenService.getRefreshToken(Long.parseLong(refreshTokenId));
                // 2. 리프레시토큰 벨리데이트 검사
                if (refreshToken != null) {
                    try {
                        ValidatedUserInfo validatedUserInfo = jwtCookieProvider.validateToken(refreshToken.getToken());
                        User user = userService.getUser(validatedUserInfo.getUsername());
                        log.info("refresh 토큰 유효 username: {}", user.getUsername());

                        String access_token = jwtCookieProvider.createAccessToken(user.getUsername()
                                , user.getRoles().stream().map(Role::getName).toList()
                                , request.getRequestURI()
                                , refreshToken.getId());

                        response = jwtCookieProvider.createCookie(response, access_token); // access_token은 쿠키에 저장
                        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                        user.getRoles().forEach(role -> authorities.add(new SimpleGrantedAuthority(role.getName())));
                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), null, authorities);
                        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                        log.info("액세스 토큰 재 갱신");
                        filterChain.doFilter(request, response);

                    } catch (TokenExpiredException tokenExpiredException) {
                        log.error("리프레시 토큰 만료");
                        log.error("Error logging in: {}", tokenExpiredException.getMessage());
                        response.setStatus(UNAUTHORIZED.value());
                        Map<String, String> error = new HashMap<>();
                        error.put("error_message", "로그인이 만료 되었습니다.");
                        response.setContentType(APPLICATION_JSON_VALUE);
                        new ObjectMapper().writeValue(response.getOutputStream(), error);
                    } catch (JWTVerificationException jwtVerificationException) {
                        log.error("리프레시 토큰 벨리데이션 오류");
                        log.error("Error logging in: {}", jwtVerificationException.getMessage());
                        response.setStatus(UNAUTHORIZED.value());
                        Map<String, String> error = new HashMap<>();
                        error.put("error_message", "로그인이 만료 되었습니다.");
                        response.setContentType(APPLICATION_JSON_VALUE);
                        new ObjectMapper().writeValue(response.getOutputStream(), error);
                    }
                } else {
                    log.error("DB에 해당 리프레시토큰 없음 id: {}", refreshTokenId);
                    response.setStatus(UNAUTHORIZED.value());
                    Map<String, String> error = new HashMap<>();
                    error.put("error_message", "로그인이 만료 되었습니다.");
                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            } else {
                log.info("액세스 토큰 유효");
                filterChain.doFilter(request, response);
            }
        }//else
    }
}
