package com.application.SecuroDoc.Service;

import com.application.SecuroDoc.DTO.User;
import com.application.SecuroDoc.Domain.TokenData;
import com.application.SecuroDoc.Enum.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import com.application.SecuroDoc.Domain.Token;

import java.util.Optional;
import java.util.function.Function;

public interface JwtService {

    String createToken(User user, Function<Token, String> tokenFunction);
    Optional<String> extractToken(HttpServletRequest request, String tokenType);
    void addCookie(HttpServletResponse response, User user, TokenType type);
    <T> T getTokenData(String token, Function<TokenData, T> tokenFunction);
    void removeCookie(HttpServletRequest request, HttpServletResponse response, String cookieName);
}
