package com.taa.auth.security.config;

import com.taa.auth.security.service.UserDetailsImpl;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationProvider implements org.springframework.security.authentication.AuthenticationProvider {

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsImpl userService;

    public AuthenticationProvider(@Lazy PasswordEncoder passwordEncoder,@Lazy UserDetailsImpl userService) {
        this.passwordEncoder = passwordEncoder;
        this.userService = userService;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName(); //name ise kullanıcı adı (sizin atadığınız birim) ifade eder
        String password = authentication.getCredentials().toString(); //credentials parolayı ifade eder

        UserDetails user = userService.loadUserByUsername(username);


        if (passwordEncoder.matches(password, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(username, password, user.getAuthorities());
        } else {
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
