package kz.zhanayev.spring.springsecurityjwtapp;

public record Tokens(String accessToken, String accessTokenExpiry,
                     String refreshToken, String refreshTokenExpiry) {
}
