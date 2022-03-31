package hanu.example.springjwtcookie.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import hanu.example.springjwtcookie.domain.RefreshToken;
import hanu.example.springjwtcookie.security.jwt.JwtCookieProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtCookieProvider jwtCookieProvider;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager, JwtCookieProvider jwtCookieProvider) {
        this.authenticationManager = authenticationManager;
        this.jwtCookieProvider = jwtCookieProvider;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        //인증 시도시 호출
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Username is : {}", username);
        log.info("Password is : {}", password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException {
        //인증 성공시 호출, 주의 아래 User는 UserDetails의 User
        User user = (User) authentication.getPrincipal();

        String refresh_token = jwtCookieProvider.createRefreshToken(user, request.getRequestURI());
        RefreshToken savedRefreshToken = jwtCookieProvider.saveRefreshToken(refresh_token);
        String access_token = jwtCookieProvider.createAccessToken(user.getUsername(), user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList(), request.getRequestURI(), savedRefreshToken.getId());

        response = jwtCookieProvider.createCookie(response, access_token); // access_token은 쿠키에 저장

        Map<String, String> message = new HashMap<>();
        message.put("success", "true");
        message.put("access_token", access_token);
        message.put("refresh_token", refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);

        new ObjectMapper().writeValue(response.getOutputStream(), message);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        log.error("unsuccessfulAuthentication ...");
        SecurityContextHolder.clearContext();

        log.error("Error logging in: {}", exception.getMessage());
        // 토큰이 유효하지 않은 경우
        response.setHeader("error", exception.getMessage());
        response.setStatus(UNAUTHORIZED.value());
        Map<String, String> error = new HashMap<>();
        error.put("error_message", exception.getMessage());
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), error);
    }
}
