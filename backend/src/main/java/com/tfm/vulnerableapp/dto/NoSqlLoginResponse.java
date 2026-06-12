package com.tfm.vulnerableapp.dto;

import java.util.List;

public record NoSqlLoginResponse(
    boolean authenticated,
    List<NoSqlUserResponse> users
) {
}
