package com.jwt.security.model.token;
import static java.util.stream.Collectors.toList;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.jwt.security.config.TokenProperties;
import com.jwt.security.model.Scopes;
import com.jwt.security.model.UserContext;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Token创建工厂类 {@link Token}.
 * @since 2018-11-28
 */
@Component
public class TokenFactory {

    @Autowired
    private TokenProperties tokenProperties;

    /**
     * 利用JJWT 生成 Token
     *
     * @param context
     * @return
     */
    public AccessToken createAccessToken(UserContext context) {
        Optional.ofNullable(context.getUsername()).orElseThrow(() -> new IllegalArgumentException("Cannot create Token without username"));
        Optional.ofNullable(context.getAuthorities()).orElseThrow(() -> new IllegalArgumentException("User doesn't have any privileges"));
        Claims claims = Jwts.claims().setSubject(context.getUsername());
        claims.put("scopes", context.getAuthorities().stream().map(Object::toString).collect(toList()));
        LocalDateTime currentTime = LocalDateTime.now();
        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuer(tokenProperties.getIssuer())
                .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
                .setExpiration(Date.from(currentTime.plusMinutes(tokenProperties.getExpirationTime())
                		.atZone(ZoneId.systemDefault())
                			.toInstant()))
                .signWith(SignatureAlgorithm.HS512, tokenProperties.getSigningKey())
                .compact();
        return new AccessToken(token, claims);
    }

    /**
     * 生成 刷新 RefreshToken
     *
     * @param userContext
     * @return
     */
    public Token createRefreshToken(UserContext userContext) {
        if (StringUtils.isBlank(userContext.getUsername())) {
            throw new IllegalArgumentException("Cannot create Token without username");
        }
        LocalDateTime currentTime = LocalDateTime.now();
        Claims claims = Jwts.claims().setSubject(userContext.getUsername());
        claims.put("scopes", Collections.singletonList(Scopes.REFRESH_TOKEN.authority()));
        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuer(tokenProperties.getIssuer())
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
                .setExpiration(Date.from(currentTime
                        .plusMinutes(tokenProperties.getRefreshExpTime())
                        .atZone(ZoneId.systemDefault()).toInstant()))
                .signWith(SignatureAlgorithm.HS512, tokenProperties.getSigningKey())
                .compact();

        return new AccessToken(token, claims);
    }
}
