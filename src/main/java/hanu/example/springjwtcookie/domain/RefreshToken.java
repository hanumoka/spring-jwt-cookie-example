package hanu.example.springjwtcookie.domain;

import lombok.*;

import javax.persistence.*;

import static javax.persistence.GenerationType.AUTO;

/**
 * TODO: 스케쥴로 만료된 토큰은 삭제해 주면 될듯하다.
 * TODO: 레디스 분리대상
 */
@Entity
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RefreshToken {
    @Id
    @GeneratedValue(strategy = AUTO)
    private Long id;
    private String token;

}
