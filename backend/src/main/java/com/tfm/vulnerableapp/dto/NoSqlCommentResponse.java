package com.tfm.vulnerableapp.dto;

public record NoSqlCommentResponse(
    String id,
    String author,
    String text,
    String visibility
) {
}
