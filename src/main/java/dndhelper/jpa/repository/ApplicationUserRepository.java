package dndhelper.jpa.repository;

import dndhelper.jpa.model.ApplicationUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ApplicationUserRepository extends JpaRepository<ApplicationUser, Long> {
    public Optional<ApplicationUser> findByUsername(String username);
}
