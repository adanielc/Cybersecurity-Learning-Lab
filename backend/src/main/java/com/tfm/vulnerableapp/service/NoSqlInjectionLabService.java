package com.tfm.vulnerableapp.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tfm.vulnerableapp.dto.*;
import jakarta.annotation.PostConstruct;
import org.bson.Document;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.BasicQuery;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class NoSqlInjectionLabService {

    private static final String USERS_COLLECTION = "lab_nosqli_users";
    private static final String COMMENTS_COLLECTION = "lab_nosqli_comments";
    private static final Set<String> FORBIDDEN_OPERATOR_TOKENS = Set.of("$ne", "$gt", "$regex", "$where");

    private final MongoTemplate mongoTemplate;
    private final ObjectMapper objectMapper;

    public NoSqlInjectionLabService(MongoTemplate mongoTemplate, ObjectMapper objectMapper) {
        this.mongoTemplate = mongoTemplate;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void initializeLabData() {
        if (!mongoTemplate.collectionExists(USERS_COLLECTION)) {
            mongoTemplate.createCollection(USERS_COLLECTION);
        }

        if (!mongoTemplate.collectionExists(COMMENTS_COLLECTION)) {
            mongoTemplate.createCollection(COMMENTS_COLLECTION);
        }

        seedUser("user-admin", "admin", "adminpass",
                "admin@vulnerable-lab.local", "ADMIN");
        seedUser("user-alice", "alice", "password123",
                "alice@vulnerable-lab.local", "USER");
        seedUser("user-bob", "bob", "password123",
                "bob@vulnerable-lab.local", "USER");
        seedUser("user-auditor", "auditor", "auditpass",
                "auditor@vulnerable-lab.local", "ADMIN");

        seedComment("comment-1", "alice", "Public comment about REST APIs", "PUBLIC");
        seedComment("comment-2", "bob", "MongoDB filters are powerful when controlled by the backend",
                "PUBLIC");
        seedComment("comment-3", "admin", "Internal moderation note for admins", "PRIVATE");
        seedComment("comment-4", "auditor", "Security review: never trust arbitrary JSON operators",
                "PRIVATE");
    }

    public NoSqlLoginResponse loginVulnerable(Map<String, Object> body) {
        /*
         * VULNERABLE: el body JSON se transforma en una query MongoDB sin validar.
         * Si el usuario envia {"username":{"$ne":null},"password":{"$ne":null}},
         * MongoDB interpreta $ne como operador y la consulta deja de ser una
         * comparacion exacta de credenciales.
         */
        List<NoSqlUserResponse> users = mongoTemplate
            .find(buildVulnerableLoginQuery(body), Document.class, USERS_COLLECTION)
            .stream()
            .map(this::toUserResponse)
            .toList();

        return new NoSqlLoginResponse(!users.isEmpty(), users);
    }

    public NoSqlLoginResponse loginSecure(NoSqlLoginRequest request) {
        String username = requireSafeString(request.username(), "username");
        String password = requireSafeString(request.password(), "password");

        List<NoSqlUserResponse> users = mongoTemplate
            .find(buildSecureLoginQuery(username, password), Document.class, USERS_COLLECTION)
            .stream()
            .map(this::toUserResponse)
            .toList();

        return new NoSqlLoginResponse(!users.isEmpty(), users);
    }

    public List<NoSqlCommentResponse> searchCommentsVulnerable(Map<String, Object> body) {
        /*
         * VULNERABLE: se acepta una query documental completa desde el cliente.
         * Operadores como $regex o $ne permiten cambiar el significado de la
         * busqueda y pueden exponer comentarios fuera del caso previsto.
         */
        return mongoTemplate
            .find(buildVulnerableCommentQuery(body), Document.class, COMMENTS_COLLECTION)
            .stream()
            .map(this::toCommentResponse)
            .toList();
    }

    public List<NoSqlCommentResponse> searchCommentsSecure(NoSqlCommentSearchRequest request) {
        String text = requireSafeString(request.text(), "text");

        return mongoTemplate
            .find(buildSecureCommentQuery(text), Document.class, COMMENTS_COLLECTION)
            .stream()
            .map(this::toCommentResponse)
            .toList();
    }

    private BasicQuery buildVulnerableLoginQuery(Map<String, Object> body) {
        return rawClientQuery(body, "login");
    }

    private BasicQuery buildVulnerableCommentQuery(Map<String, Object> body) {
        return rawClientQuery(body, "busqueda");
    }

    private Query buildSecureLoginQuery(String username, String password) {
        return new Query()
            .addCriteria(Criteria.where("username").is(username))
            .addCriteria(Criteria.where("password").is(password));
    }

    private Query buildSecureCommentQuery(String text) {
        return new Query()
            .addCriteria(Criteria.where("text").regex(Pattern.quote(text), "i"))
            .addCriteria(Criteria.where("visibility").is("PUBLIC"));
    }

    private BasicQuery rawClientQuery(Map<String, Object> body, String scenario) {
        try {
            String json = objectMapper.writeValueAsString(body == null ? Map.of() : body);
            return new BasicQuery(Document.parse(json));
        } catch (JsonProcessingException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "El JSON del escenario de " + scenario + " no es valido", ex);
        }
    }

    private String requireSafeString(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "El campo " + fieldName + " es obligatorio");
        }

        String normalized = value.trim();
        if (containsForbiddenOperatorToken(normalized)) {
            throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "El campo " + fieldName + " contiene un operador MongoDB no permitido"
            );
        }

        return normalized;
    }

    private boolean containsForbiddenOperatorToken(String value) {
        return FORBIDDEN_OPERATOR_TOKENS.stream().anyMatch(value::contains);
    }

    private void seedUser(String id, String username, String password, String email, String role) {
        Document user = new Document("_id", id)
            .append("username", username)
            .append("password", password)
            .append("email", email)
            .append("role", role);

        mongoTemplate.save(user, USERS_COLLECTION);
    }

    private void seedComment(String id, String author, String text, String visibility) {
        Document comment = new Document("_id", id)
            .append("author", author)
            .append("text", text)
            .append("visibility", visibility);

        mongoTemplate.save(comment, COMMENTS_COLLECTION);
    }

    private NoSqlUserResponse toUserResponse(Document document) {
        return new NoSqlUserResponse(
            document.getString("_id"),
            document.getString("username"),
            document.getString("email"),
            document.getString("role")
        );
    }

    private NoSqlCommentResponse toCommentResponse(Document document) {
        return new NoSqlCommentResponse(
            document.getString("_id"),
            document.getString("author"),
            document.getString("text"),
            document.getString("visibility")
        );
    }
}
