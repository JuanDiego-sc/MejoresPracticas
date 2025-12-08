package com.laboratorio.gestionlab.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        // Recursos estáticos públicos
                        .requestMatchers("/css/**", "/js/**", "/img/**").permitAll()
                        // Logout público
                        .requestMatchers("/logout").permitAll()
                        // Operaciones de escritura públicas (POST, PUT, DELETE)
                        .requestMatchers(HttpMethod.POST, "/**").permitAll()
                        .requestMatchers(HttpMethod.PUT, "/**").permitAll()
                        .requestMatchers(HttpMethod.DELETE, "/**").permitAll()
                        // Operaciones GET requieren autenticación
                        .requestMatchers(HttpMethod.GET, "/**").authenticated()
                        // Cualquier otra solicitud requiere autenticación
                        .anyRequest().authenticated()
                )
                // OAuth2 Login con Keycloak
                .oauth2Login(oauth2 -> oauth2
                        .defaultSuccessUrl("/index", true)
                        .permitAll()
                )
                // OAuth2 Resource Server para APIs REST con JWT
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> {})
                )
                // Logout con redirección a Keycloak
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(oidcLogoutSuccessHandler())
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                // Sesiones para web (OAuth2 Login) pero también soporta stateless para API REST
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                );

        return http.build();
    }

    @Bean
    public LogoutSuccessHandler oidcLogoutSuccessHandler() {
        return new LogoutSuccessHandler() {
            @Override
            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, 
                                        Authentication authentication) throws IOException {
                if (authentication != null && authentication.getPrincipal() instanceof OidcUser) {
                    OidcUser user = (OidcUser) authentication.getPrincipal();
                    String idToken = user.getIdToken().getTokenValue();
                    String logoutUrl = "http://localhost:8080/realms/Vet_auth_demo/protocol/openid-connect/logout" +
                            "?post_logout_redirect_uri=http://localhost:5003/" +
                            "&id_token_hint=" + idToken;
                    response.sendRedirect(logoutUrl);
                } else {
                    response.sendRedirect("/");
                }
            }
        };
    }
}
