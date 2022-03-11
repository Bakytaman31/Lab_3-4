package com.example.agency.repositories;

import com.example.agency.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends JpaRepository<User,Long> {

    User findByEmailAndUserPassword(String e,String p);

    User findByEmail(String email);

    boolean existsByEmail(String email);




}
