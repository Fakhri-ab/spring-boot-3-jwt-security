package com.fakhri.security.user;

import com.fakhri.security.token.Token;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
// UserDetails est une interface de Spring Security permettant
// de fournir des informations sur l'utilisateur lors du processus d'authentification,
// telles que le nom d'utilisateur, le mot de passe et les rôles
public class User implements UserDetails {

    @Id
    @GeneratedValue
    private Integer id;
    private String firstname;
    private String lastname;
    private String email;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @OneToMany(mappedBy = "user")
    private List<Token> tokens;

    // Cette méthode renvoie une liste contenant le rôle de l'utilisateur sous forme d'objet
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    //Cette méthode indique que le compte de l'utilisateur n'expire jamais, en retournant toujours true
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // Cette méthode indique que le compte de l'utilisateur n'est jamais verrouillé, en retournant toujours true
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
   //Cette méthode indique que les informations d'identification de l'utilisateur (comme le mot de passe) ne expirent jamais, en retournant toujours true
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    // Cette méthode indique que le compte de l'utilisateur est toujours activé, en retournant toujours true
    @Override
    public boolean isEnabled() {
        return true;
    }
}
