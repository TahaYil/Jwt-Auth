package com.taa.auth.security.config;

import com.taa.auth.security.service.UserDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.Customizer;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity

public class SecurityConfiguration {


    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserDetailsImpl userDetails;
    private final AuthenticationProvider authenticationProvider;


    private static final Logger logger = LoggerFactory.getLogger(SecurityConfiguration.class);

    public SecurityConfiguration(JwtAuthenticationFilter jwtAuthenticationFilter, UserDetailsImpl userDetails, AuthenticationProvider authenticationProvider) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userDetails = userDetails;
        this.authenticationProvider = authenticationProvider;
    }


    //    @Bean
  //  public JwtAuthenticationFilter jwtAuthenticationFilter(){
    //    return new JwtAuthenticationFilter();
    //}
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity security) throws Exception {
        logger.info("Configuring security filter chain");
        return security
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(Customizer.withDefaults())
                .authorizeHttpRequests(
                        authorize -> authorize.requestMatchers("v1/auth/**","/error")
                                .permitAll()
                                .anyRequest()
                                .hasAuthority("ROLE_USER"))
                .userDetailsService(userDetails)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter , UsernamePasswordAuthenticationFilter.class)
                .build();

    }




    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


}
