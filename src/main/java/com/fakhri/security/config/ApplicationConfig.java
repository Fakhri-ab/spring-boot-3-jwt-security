package com.fakhri.security.config;

import com.fakhri.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;


// Cette classe configure l'authentification dans Spring Security,
// définissant les composants nécessaires tels que le service utilisateur,
// le fournisseur d'authentification, l'encodeur de mot de passe et l'AuthenticationManager
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository repository;


    //Cette configuration Spring crée un service de détails utilisateur
    // qui utilise une fonction lambda pour rechercher un utilisateur par adresse e-mail
    // dans un référentiel (repository) et génère une exception si l'utilisateur n'est pas trouvé
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    //Cette configuration crée un bean AuthenticationProvider pour l'authentification,
    // configuré avec un service utilisateur et un encodeur de mot de passe
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Cette configuration Spring crée un bean AuthenticationManager en utilisant AuthenticationConfiguration.
    // Il récupère l'instance de AuthenticationManager à partir de la configuration.
    // L'AuthenticationManager est essentiel dans Spring Security pour gérer les opérations d'authentification
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

}
