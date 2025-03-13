package com.taa.auth.security.controller;

import com.taa.auth.security.dto.AuthenticationRequest;
import com.taa.auth.security.dto.AuthenticationResponse;
import com.taa.auth.security.dto.RegisterRequest;
import com.taa.auth.security.model.User;
import com.taa.auth.security.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

@Controller
@RequiredArgsConstructor
@RequestMapping("v1/auth")
public class AuthenticationController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(this.authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(this.authService.authenticate(request));
    }

    @GetMapping()
    public ResponseEntity<List<User>> getAll(){
        return ResponseEntity.ok(this.authService.getAll());
    }
}
