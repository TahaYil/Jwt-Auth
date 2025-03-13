package com.taa.auth.security.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("v1/auth-test")
public class TestController {
    @GetMapping("/string")
    public String hello(){
        return "hello from secure end-point!!";
    }
}
