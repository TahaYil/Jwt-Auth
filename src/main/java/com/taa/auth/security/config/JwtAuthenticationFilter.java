package com.taa.auth.security.config;

import com.taa.auth.security.service.UserDetailsImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsImpl userDetailsImpl;
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsImpl userDetailsImpl) {
        this.jwtService = jwtService;
        this.userDetailsImpl = userDetailsImpl;
    }


    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        final String authHeader=request.getHeader("Authorization");

        logger.info("Authorization Header: {}", authHeader);

        if(authHeader==null || !authHeader.startsWith("Bearer ")){
            logger.warn("No JWT token found in request headers or Authorization header does not start with 'Bearer'");
            filterChain.doFilter(request,response);
            return;
        }

        final String token = authHeader.substring(7);   //7 ve sonrasını alır toke burda
        final String email = this.jwtService.extractUsername(token);
        logger.info("JWT token extracted, email: {}", email);

        if(email!=null && SecurityContextHolder.getContext().getAuthentication()==null){
            UserDetails userDetails = userDetailsImpl.loadUserByUsername(email);
            logger.info("UserDetails loaded for user: {}", email);

            if(jwtService.isValidToken(token,userDetails)){
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails , null , userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
                logger.info("authentication holder worked -> " + SecurityContextHolder.getContext());
            }
            else {
                logger.warn("Invalid JWT token for user: {}", email);
            }

        }else {
            logger.warn("JWT token is null or SecurityContext already has an authentication");
        }
        filterChain.doFilter(request,response);



    }
}

