package dndhelper.jpa.repository;

import dndhelper.jpa.model.ApplicationUser;
import dndhelper.jpa.model.BasicAuthUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface BasicAuthUserRepository extends JpaRepository<BasicAuthUser, Long> {
    public Optional<BasicAuthUser> findByApplicationUser(ApplicationUser user);
}

