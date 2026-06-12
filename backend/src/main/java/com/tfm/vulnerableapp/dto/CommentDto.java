package com.tfm.vulnerableapp.dto;

import java.time.Instant;

public record CommentDto(
    String id,
    String author,
    String content,
    Instant createdAt
) {
}
