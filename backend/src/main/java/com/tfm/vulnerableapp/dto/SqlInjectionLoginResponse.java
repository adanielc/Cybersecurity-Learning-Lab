package com.tfm.vulnerableapp.dto;

import java.util.List;

public record SqlInjectionLoginResponse(
        boolean authenticated,
        int matchedUsers,
        List<SqlInjectionUserResponse> users
) {
}
