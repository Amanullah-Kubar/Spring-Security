package com.example.demo.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;



@Component
public class JWTUtils {
    private static final Logger logger = LoggerFactory.getLogger(JWTUtils.class);

    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    public String getJWTFromHeader(HttpServletRequest request) {

        // Extracting token from header
        String bearerToken = request.getHeader("Authorization");

        logger.debug("bearerToken: {}", bearerToken);

        // checking weather the token is null or not
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public String generateJWTFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();

    }

    public String getUsernameFromJWT(String jwt) {
        return Jwts.parser().verifyWith((SecretKey) key())
                .build()
                .parseClaimsJws(jwt)
                .getBody()
                .getSubject();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }


    public Boolean validateJWT(String jwt) {
        try {
            System.out.println("Validating JWT");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseClaimsJws(jwt);
            return true;
        }catch (MalformedJwtException e) {
            System.out.println(e.getMessage());
            logger.error("invalid",e);
        }catch (ExpiredJwtException e) {
            logger.error("ExpiredJwtException", e);
        }catch (UnsupportedJwtException e) {
            logger.error("UnsupportedJwtException", e);
        }catch (IllegalArgumentException e) {
            logger.error("IllegalArgumentException", e);
        }
        return false;
    }

}
