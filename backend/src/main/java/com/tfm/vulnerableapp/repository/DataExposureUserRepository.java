package com.tfm.vulnerableapp.repository;

import com.tfm.vulnerableapp.entity.DataExposureUserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DataExposureUserRepository extends JpaRepository<DataExposureUserEntity, Long> {
}
