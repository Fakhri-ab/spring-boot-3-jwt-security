package com.fakhri.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Désactivation de la protection CSRF
                .cors()
                .and()
                .csrf()
                .disable()
                // Autoriser toutes les requêtes HTTP sur le chemin "/api/v1/auth/**" sans authentification
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**")
                .permitAll()
                // Toutes les autres requêtes nécessitent une authentification
                .anyRequest()
                .authenticated()
                 .and()
                // Configuration de la gestion des sessions (pas de sessions dans notre cas)
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // Configuration de l'AuthenticationProvider
                .authenticationProvider(authenticationProvider)
                // Ajout du filtre JwtAuthenticationFilter avant le filtre UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .logout()
                .logoutUrl("/api/v1/auth/logout")
                .addLogoutHandler(logoutHandler)
                //Cela signifie qu'après la déconnexion, le contexte d'authentification de l'utilisateur est effacé
                .logoutSuccessHandler((request, response, authentication) -> SecurityContextHolder.clearContext()) ;
        ;
// Retourne la configuration sécurisée
        return http.build();
    }

}
