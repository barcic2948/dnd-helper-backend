package dndhelper.jpa.model;

import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "BASIC_AUTH_USER")
public class BasicAuthUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "application_user_id", referencedColumnName = "id", nullable = false)
    private ApplicationUser applicationUser;

    @Column(name = "password", nullable = false)
    private String password;
}
