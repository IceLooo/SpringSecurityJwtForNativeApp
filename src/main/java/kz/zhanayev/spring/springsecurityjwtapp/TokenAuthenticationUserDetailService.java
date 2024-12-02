package kz.zhanayev.spring.springsecurityjwtapp;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.time.Instant;

public class TokenAuthenticationUserDetailService implements
        AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private final JdbcTemplate jdbcTemplate;
    public TokenAuthenticationUserDetailService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken authenticationToken) throws UsernameNotFoundException {
        if (authenticationToken.getPrincipal() instanceof Token token) {
            return new TokenUser(token.subject(), "nopassword", true, true, token.expiresAt().isAfter(Instant.now()), true,
                    token.authorities().stream().
                    map(SimpleGrantedAuthority::new).
                    toList(), token);
        }

        throw new UsernameNotFoundException("Principial must be of type Token");

    }
}
