package com.taa.auth.security.service;

import com.taa.auth.security.config.JwtService;
import com.taa.auth.security.dto.AuthenticationRequest;
import com.taa.auth.security.dto.AuthenticationResponse;
import com.taa.auth.security.dto.RegisterRequest;
import com.taa.auth.security.model.Role;
import com.taa.auth.security.model.User;
import com.taa.auth.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;


    public AuthenticationResponse register(RegisterRequest request) {
        User user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .role(Role.USER)
                .password(passwordEncoder.encode(request.getPassword()))
                .build();
        this.userRepository.save(user);

        String token = this.jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(token)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail() ,
                        request.getPassword()
                )
        );
        User user = this.userRepository.findByEmail(request.getEmail()).orElseThrow();

        String token = this.jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(token)
                .build();

    }

    public List<User> getAll() {
        return this.userRepository.findAll();
    }
}
