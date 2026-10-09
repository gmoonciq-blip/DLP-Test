package com.company.dlp.test;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;
import java.util.stream.Collectors;

public class EnterpriseDataProcessor {

    private final ExecutorService executorService;
    private final Map<String, UserRecord> cache = new ConcurrentHashMap<>();

    public EnterpriseDataProcessor(int threads) {
        this.executorService = Executors.newFixedThreadPool(threads);
    }

    public CompletableFuture<List<ProcessedUser>> processUsers(List<UserRecord> users) {

        List<CompletableFuture<ProcessedUser>> futures = users.stream()
                .map(user -> CompletableFuture.supplyAsync(() -> processUser(user), executorService))
                .collect(Collectors.toList());

        return CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                .thenApply(v -> futures.stream()
                        .map(CompletableFuture::join)
                        .collect(Collectors.toList()));
    }

    private ProcessedUser processUser(UserRecord user) {

        cache.put(user.getUserId(), user);

        String normalizedEmail = Optional.ofNullable(user.getEmail())
                .map(String::trim)
                .map(String::toLowerCase)
                .orElse("unknown@domain.com");

        int score = calculateRiskScore(user);

        return ProcessedUser.builder()
                .userId(user.getUserId())
                .email(normalizedEmail)
                .riskScore(score)
                .processedAt(LocalDateTime.now())
                .build();
    }

    private int calculateRiskScore(UserRecord user) {

        int ageFactor = user.getAge() > 50 ? 20 : 10;

        int accessFactor = switch (user.getAccessLevel()) {
            case ADMIN -> 50;
            case POWER_USER -> 30;
            case STANDARD -> 10;
        };

        return ageFactor + accessFactor;
    }

    public void shutdown() {
        executorService.shutdown();
    }

    public static void main(String[] args) throws Exception {

        EnterpriseDataProcessor processor =
                new EnterpriseDataProcessor(4);

        List<UserRecord> users = Arrays.asList(
                new UserRecord(
                        UUID.randomUUID().toString(),
                        "user1@contoso.com",
                        35,
                        AccessLevel.ADMIN
                ),
                new UserRecord(
                        UUID.randomUUID().toString(),
                        "user2@contoso.com",
                        28,
                        AccessLevel.STANDARD
                )
        );

        List<ProcessedUser> result =
                processor.processUsers(users).get();

        result.forEach(System.out::println);

        processor.shutdown();
    }
}

enum AccessLevel {
    ADMIN,
    POWER_USER,
    STANDARD
}

class UserRecord {

    private final String userId;
    private final String email;
    private final int age;
    private final AccessLevel accessLevel;

    public UserRecord(
            String userId,
            String email,
            int age,
            AccessLevel accessLevel) {

        this.userId = userId;
        this.email = email;
        this.age = age;
        this.accessLevel = accessLevel;
    }

    public String getUserId() {
        return userId;
    }

    public String getEmail() {
        return email;
    }

    public int getAge() {
        return age;
    }

    public AccessLevel getAccessLevel() {
        return accessLevel;
    }
}

class ProcessedUser {

    private String userId;
    private String email;
    private int riskScore;
    private LocalDateTime processedAt;

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private final ProcessedUser user = new ProcessedUser();

        public Builder userId(String userId) {
            user.userId = userId;
            return this;
        }

        public Builder email(String email) {
            user.email = email;
            return this;
        }

        public Builder riskScore(int riskScore) {
            user.riskScore = riskScore;
            return this;
        }

        public Builder processedAt(LocalDateTime processedAt) {
            user.processedAt = processedAt;
            return this;
        }

        public ProcessedUser build() {
            return user;
        }
    }

    @Override
    public String toString() {
        return "ProcessedUser{" +
                "userId='" + userId + '\'' +
                ", email='" + email + '\'' +
                ", riskScore=" + riskScore +
                ", processedAt=" + processedAt +
                '}';
    }
}