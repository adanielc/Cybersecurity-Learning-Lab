package com.tfm.vulnerableapp.repository;

import com.tfm.vulnerableapp.entity.BolaUserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface BolaUserRepository extends JpaRepository<BolaUserEntity, Long> {
}
