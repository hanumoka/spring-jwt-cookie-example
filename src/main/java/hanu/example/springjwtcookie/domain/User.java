package hanu.example.springjwtcookie.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.web.context.annotation.ApplicationScope;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

import static javax.persistence.GenerationType.AUTO;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@ApplicationScope
@Getter
@Setter
public class User {
    @Id
    @GeneratedValue(strategy = AUTO)
    private Long id;
    private String name;
    private String username;
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    private Collection<Role> roles = new ArrayList<>();

//    @OneToOne(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
//    @JoinColumn(name = "refreshToken")
//    private RefreshToken refreshToken;

//    @OneToMany
//    private Collection<BlackListToken> blackListTokens;
}
