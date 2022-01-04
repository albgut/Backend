package fr.periscol.backend.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Component
public class TokenAuthenticationService {

    private static TokenAuthenticationService _instance;

    private static final Key KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    private static final String TOKEN_PREFIX = "Bearer";
    private static final String HEADER_STRING = "Authorization";
    private static final String AUTHORITIES_KEY = "scopes";

    public static TokenAuthenticationService getInstance() {
        return _instance;
    }

    @Value("${periscol.security.token.ttl}")
    private long expirationTime; // 10 jours

    public void addAuthentication(HttpServletResponse res, Authentication auth) {
        final String authorities = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        final String jwt = Jwts.builder().setSubject(auth.getName())
                .claim(AUTHORITIES_KEY, authorities)
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(KEY).compact();
        res.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + jwt);
    }

    public Authentication getAuthentication(HttpServletRequest request) {
        if(!request.getRequestURI().contains("/login")) {
            final String token = request.getHeader(HEADER_STRING);
            if (token != null) {
                final var user = Jwts.parserBuilder().setSigningKey(KEY)
                        .build()
                        .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                        .getBody();
                final Collection<? extends GrantedAuthority> authorities =
                        Arrays.stream(user.get(AUTHORITIES_KEY).toString().split(","))
                                .map(SimpleGrantedAuthority::new)
                                .toList();
                return user.getSubject() != null ? new UsernamePasswordAuthenticationToken(user.getSubject(), null, authorities) : null;
            }
        }
        return null;
    }

    private TokenAuthenticationService() {
        _instance = this;
    }

}
