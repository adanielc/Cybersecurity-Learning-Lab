package com.tfm.vulnerableapp.service;

import com.tfm.vulnerableapp.dto.SeedDataDatasetResponse;
import com.tfm.vulnerableapp.dto.SeedDataOverviewResponse;
import org.bson.Document;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class SeedDataService {

    private final JdbcTemplate jdbcTemplate;
    private final MongoTemplate mongoTemplate;

    public SeedDataService(JdbcTemplate jdbcTemplate, MongoTemplate mongoTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        this.mongoTemplate = mongoTemplate;
    }

    public SeedDataOverviewResponse readOverview() {
        List<SeedDataDatasetResponse> sqlTables = readSqlTables();
        List<SeedDataDatasetResponse> noSqlCollections = readNoSqlCollections();

        return new SeedDataOverviewResponse(
            sqlTables.size(),
            noSqlCollections.size(),
            sqlTables.size() + noSqlCollections.size(),
            sqlTables,
            noSqlCollections
        );
    }

    private List<SeedDataDatasetResponse> readSqlTables() {
        List<String> tableNames = jdbcTemplate.queryForList("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_type = 'BASE TABLE'
              AND table_name LIKE 'lab\\_%' ESCAPE '\\'
            ORDER BY table_name
            """, String.class);

        List<SeedDataDatasetResponse> datasets = new ArrayList<>();
        for (String tableName : tableNames) {
            List<String> columns = jdbcTemplate.queryForList("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = ?
                ORDER BY ordinal_position
                """, String.class, tableName);

            List<String> indexes = jdbcTemplate.queryForList("""
                SELECT indexname
                FROM pg_indexes
                WHERE schemaname = 'public'
                  AND tablename = ?
                ORDER BY indexname
                """, String.class, tableName);

            List<Map<String, Object>> rows = jdbcTemplate.queryForList("SELECT * FROM \"" + tableName + "\"")
                .stream()
                .map(this::normalizeRow)
                .toList();

            datasets.add(new SeedDataDatasetResponse(
                tableName,
                "sql",
                rows.size(),
                columns,
                indexes,
                rows
            ));
        }

        return datasets;
    }

    private List<SeedDataDatasetResponse> readNoSqlCollections() {
        List<String> collectionNames = mongoTemplate.getCollectionNames().stream()
            .filter(name -> name.startsWith("lab_"))
            .sorted()
            .toList();

        List<SeedDataDatasetResponse> datasets = new ArrayList<>();
        for (String collectionName : collectionNames) {
            List<Document> documents = mongoTemplate.findAll(Document.class, collectionName);
            List<Map<String, Object>> rows = documents.stream()
                .map(this::normalizeDocument)
                .toList();

            List<String> columns = rows.stream()
                .flatMap(row -> row.keySet().stream())
                .distinct()
                .collect(Collectors.toList());

            List<String> indexes = mongoTemplate.getCollection(collectionName)
                .listIndexes(Document.class)
                .into(new ArrayList<>())
                .stream()
                .map(index -> String.valueOf(index.get("name")))
                .toList();

            datasets.add(new SeedDataDatasetResponse(
                collectionName,
                "nosql",
                rows.size(),
                columns,
                indexes,
                rows
            ));
        }

        return datasets;
    }

    private Map<String, Object> normalizeRow(Map<String, Object> row) {
        Map<String, Object> normalized = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : row.entrySet()) {
            normalized.put(entry.getKey(), normalizeValue(entry.getValue()));
        }
        return normalized;
    }

    private Map<String, Object> normalizeDocument(Document document) {
        Map<String, Object> normalized = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : document.entrySet()) {
            normalized.put(entry.getKey(), normalizeValue(entry.getValue()));
        }
        return normalized;
    }

    private Object normalizeValue(Object value) {
        if (value == null) {
            return null;
        }

        if (value instanceof Timestamp timestamp) {
            return timestamp.toInstant().toString();
        }

        if (value instanceof Date date) {
            return Instant.ofEpochMilli(date.getTime()).toString();
        }

        if (value instanceof TemporalAccessor) {
            return String.valueOf(value);
        }

        if (value instanceof Document document) {
            return normalizeDocument(document);
        }

        if (value instanceof Map<?, ?> map) {
            Map<String, Object> normalized = new LinkedHashMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                normalized.put(String.valueOf(entry.getKey()), normalizeValue(entry.getValue()));
            }
            return normalized;
        }

        if (value instanceof Collection<?> collection) {
            return collection.stream().map(this::normalizeValue).toList();
        }

        return value;
    }
}
