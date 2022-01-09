package com.cos.security1.repository;

import com.cos.security1.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

// @Repostiory 어노테이션 없이 IoC 됨. JpaRepository를 상속했기 때문
public interface UserRepository extends JpaRepository<User, Integer> {
    public User findByUsername(String username);
}
