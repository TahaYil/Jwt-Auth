package com.taa.auth.security.config;


import com.taa.auth.security.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

import java.util.function.Function;

@Service
public class JwtService {


    private final static String SECRET_KEY="895b3607810a3b5b62e8a0c07eefb61b90eb6d02c422f638ebb223995eb21ce15fbdf71f1ec0d3dd001f512e321e5f35ffe6269f4cf5f83abf8061d00b3b2eaa";

    private static final Logger logger = LoggerFactory.getLogger(JwtService.class);
    public String extractUsername(String token) {
        String username = extractClaim(token, Claims::getSubject);
        logger.info("Extracted username: {}", username);
        return username;

    }

    public String generateToken(User user){
        return  Jwts.builder()
                .subject(user.getEmail())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + 24*60*60*1000))
                .signWith(getSignInKey())
                .compact();


    }



    public boolean isValidToken(String token , UserDetails userDetails){
        final String username=extractUsername(token);
        boolean isValid = username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        logger.info("Token validity check for user: {}, isValid: {}", username, isValid);
        return isValid;
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token , Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){
        Claims claims=extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private SecretKey getSignInKey() {
        byte[] keyBytes= Decoders.BASE64URL.decode(SECRET_KEY);

        return Keys.hmacShaKeyFor(keyBytes);
    }
}
