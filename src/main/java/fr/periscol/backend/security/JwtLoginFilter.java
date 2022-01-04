package fr.periscol.backend.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Collections;

public class JwtLoginFilter extends AbstractAuthenticationProcessingFilter {

    private static final String AUTHORIZATION_HEADER = "Authorization";

    protected JwtLoginFilter(String url, AuthenticationManager authManager) {
        super(url, authManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = null;
        String password = null;
        if(request.getHeader(AUTHORIZATION_HEADER) != null) {
            final String ident = request.getHeader(AUTHORIZATION_HEADER).replace("Basic ", "");
            final var idents = (new String(Base64.getDecoder().decode(ident))).split(":");
            username = idents[0];
            password = idents[1];
        }

        return getAuthenticationManager()
                .authenticate(new UsernamePasswordAuthenticationToken(username, password, Collections.emptyList()));
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // Write Authorization to Headers of Response.
        TokenAuthenticationService.getInstance().addAuthentication(response, authResult);
        final String authorizationString = response.getHeader(AUTHORIZATION_HEADER);
        System.out.println("Authorization String=" + authorizationString);
    }
}
