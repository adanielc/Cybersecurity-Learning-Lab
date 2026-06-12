package com.tfm.vulnerableapp.service;

import com.tfm.vulnerableapp.dto.CommentCreateRequest;
import com.tfm.vulnerableapp.dto.CommentDto;
import jakarta.annotation.PostConstruct;
import org.bson.Document;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;
import org.springframework.web.util.HtmlUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@Service
public class XssLabService {

    private static final String COMMENTS_COLLECTION = "lab_xss_comments";

    private final MongoTemplate mongoTemplate;

    public XssLabService(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

    @PostConstruct
    public void seedData() {
        if (!mongoTemplate.collectionExists(COMMENTS_COLLECTION)) {
            mongoTemplate.createCollection(COMMENTS_COLLECTION);
        }

        seed("xss-1", "alice", "Comentario seguro de bienvenida", Instant.parse("2026-05-02T10:00:00Z"));
        seed("xss-2", "bob", "<strong>HTML permitido en modo vulnerable</strong>", Instant.parse("2026-05-02T10:05:00Z"));
        seed("xss-3", "attacker", "<img src=x onerror=alert('XSS laboratorio')>", Instant.parse("2026-05-02T10:10:00Z"));
    }

    public CommentDto createVulnerable(CommentCreateRequest request) {
        CommentDto comment = createAndStore(request, false);
        /*
         * VULNERABLE: se almacena y se devuelve el contenido tal cual.
         * Si la vista usa v-html, cualquier HTML o evento inline del usuario
         * se ejecuta en el navegador.
         */
        return comment;
    }

    public List<CommentDto> listVulnerable() {
        return readComments(false);
    }

    public CommentDto createSecure(CommentCreateRequest request) {
        /*
         * SECURE: el contenido se neutraliza al salir por la API. El texto
         * peligroso deja de interpretarse como HTML en el frontend.
         */
        CommentDto comment = createAndStore(request, false);
        return new CommentDto(comment.id(), comment.author(), HtmlUtils.htmlEscape(comment.content()), comment.createdAt());
    }

    public List<CommentDto> listSecure() {
        return readComments(true);
    }

    private CommentDto createAndStore(CommentCreateRequest request, boolean secureView) {
        String author = normalize(request.author());
        String content = normalize(request.content());
        Instant createdAt = Instant.now();
        String id = UUID.randomUUID().toString();

        Document document = new Document("_id", id)
            .append("author", author)
            .append("content", content)
            .append("createdAt", createdAt);

        mongoTemplate.save(document, COMMENTS_COLLECTION);

        String returnedContent = secureView ? HtmlUtils.htmlEscape(content) : content;
        return new CommentDto(id, author, returnedContent, createdAt);
    }

    private List<CommentDto> readComments(boolean secureView) {
        Query query = new Query().addCriteria(Criteria.where("content").exists(true));
        List<Document> documents = mongoTemplate.find(query, Document.class, COMMENTS_COLLECTION);
        List<CommentDto> comments = new ArrayList<>();

        for (Document document : documents) {
            String content = document.getString("content");
            comments.add(new CommentDto(
                document.getString("_id"),
                document.getString("author"),
                secureView ? HtmlUtils.htmlEscape(content) : content,
                document.getDate("createdAt").toInstant()
            ));
        }

        comments.sort(Comparator.comparing(CommentDto::createdAt).reversed());
        return comments;
    }

    private void seed(String id, String author, String content, Instant createdAt) {
        if (mongoTemplate.exists(new Query(Criteria.where("_id").is(id)), COMMENTS_COLLECTION)) {
            return;
        }

        Document document = new Document("_id", id)
            .append("author", author)
            .append("content", content)
            .append("createdAt", createdAt);

        mongoTemplate.save(document, COMMENTS_COLLECTION);
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim();
    }
}
