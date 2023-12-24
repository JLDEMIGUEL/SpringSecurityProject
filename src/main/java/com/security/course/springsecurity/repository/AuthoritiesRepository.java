package com.security.course.springsecurity.repository;

import com.security.course.springsecurity.model.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuthoritiesRepository extends JpaRepository<Authority, Long> {

    List<Authority> findAllByCustomerId(int customerId);
}
