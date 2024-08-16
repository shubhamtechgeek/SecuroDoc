package com.application.SecuroDoc.Security;

import com.application.SecuroDoc.Service.JwtService;
import com.application.SecuroDoc.Service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SecuroHttpConfigurer extends AbstractHttpConfigurer<SecuroHttpConfigurer, HttpSecurity> {
    private final SecuroAuthorizationFilter authorizationFilter;
    private final SecuroAuthenticationProvider apiAuthenticationProvider;
    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationConfiguration authenticationConfiguration;

    @Override
    public void init(HttpSecurity http) throws Exception {
        http.authenticationProvider(apiAuthenticationProvider);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.addFilterBefore(authorizationFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterAfter(new SecuroAuthenticationFilter(authenticationConfiguration.getAuthenticationManager(), userService, jwtService), UsernamePasswordAuthenticationFilter.class);
    }
}
