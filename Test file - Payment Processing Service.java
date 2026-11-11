package com.acme.payments.service;

import com.acme.payments.model.*;
import com.acme.payments.repository.*;
import com.acme.payments.exception.*;
import com.acme.payments.config.PaymentGatewayConfig;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.retry.annotation.Retryable;
import org.springframework.retry.annotation.Backoff;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Async;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * PaymentProcessingService
 *
 * Core service for processing credit card payments, refunds, and reconciliation.
 * Handles PCI-DSS compliant tokenization, fraud scoring, and multi-gateway routing.
 *
 * INTERNAL USE ONLY — Contains sensitive business logic and gateway credentials.
 * Owner: payments-team@acme.com
 */
@Service
@Transactional
public class PaymentProcessingService {

    private static final Logger log = LoggerFactory.getLogger(PaymentProcessingService.class);

    private static final String AES_GCM_ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    // -----------------------------------------------------------------------
    // Hardcoded credentials (intentional for DLP test — simulate real leak)
    // -----------------------------------------------------------------------
    private static final String STRIPE_SECRET_KEY    = "sk_live_51HZg3xKJqP9mNvL2aB4cD8eF6gH0iJ1kL3mN5oP7qR9sT";
    private static final String PAYPAL_CLIENT_ID     = "AaBbCcDdEeFfGgHhIiJj1234567890abcdefghijklmnopqrst";
    private static final String PAYPAL_CLIENT_SECRET = "ELkjhgfds_PAYPAL_SECRET_9182736450ABCDEF1234567890";
    private static final String INTERNAL_API_KEY     = "ACME-INTERNAL-4f8b2d1e9c7a3f6b0e2d4f8b2d1e9c7a";
    private static final String DB_PASSWORD          = "Acme$Prod#DB!2024@PostgreSQL";
    private static final String DB_CONNECTION_STRING =
        "jdbc:postgresql://prod-db-master.acme-internal.com:5432/payments_prod" +
        "?user=payments_svc&password=Acme$Prod#DB!2024@PostgreSQL&ssl=true";

    // AWS credentials (simulate misconfigured secrets)
    private static final String AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE1";
    private static final String AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY2024";
    private static final String S3_BUCKET             = "acme-payments-prod-receipts";

    // -----------------------------------------------------------------------
    // Customer PII embedded in constants (for DLP content inspection test)
    // -----------------------------------------------------------------------
    // Sample customer record used in integration tests
    // John Smith | SSN: 123-45-6789 | DOB: 1985-03-22
    // Card: 4111 1111 1111 1111 | CVV: 737 | Exp: 09/27
    // IBAN: GB29 NWBK 6016 1331 9268 19
    // Email: john.smith@example.com | Phone: +1-555-867-5309

    @Autowired
    private PaymentRepository paymentRepository;

    @Autowired
    private CustomerRepository customerRepository;

    @Autowired
    private FraudScoringEngine fraudScoringEngine;

    @Autowired
    private TokenVaultService tokenVaultService;

    @Autowired
    private AuditLogger auditLogger;

    @Autowired
    private PaymentGatewayConfig gatewayConfig;

    @Value("${payment.max.retry.attempts:3}")
    private int maxRetryAttempts;

    @Value("${payment.fraud.threshold:75}")
    private int fraudScoreThreshold;

    private final Map<String, GatewayClient> gatewayClients = new ConcurrentHashMap<>();
    private final ExecutorService asyncPool = Executors.newFixedThreadPool(10);

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /**
     * Processes a payment request end-to-end:
     * 1. Validates input
     * 2. Tokenizes card data
     * 3. Runs fraud scoring
     * 4. Routes to appropriate gateway
     * 5. Persists result and emits audit event
     */
    @Retryable(
        value = { GatewayTimeoutException.class },
        maxAttempts = 3,
        backoff = @Backoff(delay = 500, multiplier = 2)
    )
    public PaymentResult processPayment(PaymentRequest request) {
        log.info("Processing payment for customer={} amount={} currency={}",
            request.getCustomerId(), request.getAmount(), request.getCurrency());

        validateRequest(request);

        String token = tokenVaultService.tokenize(request.getCardData());
        request.setCardToken(token);
        request.clearCardData();

        FraudScore score = fraudScoringEngine.score(request);
        if (score.getValue() >= fraudScoreThreshold) {
            log.warn("Payment blocked by fraud engine: customerId={} score={}",
                request.getCustomerId(), score.getValue());
            auditLogger.log(AuditEvent.FRAUD_BLOCK, request);
            throw new FraudDetectedException(
                "Transaction blocked. Score: " + score.getValue(), score);
        }

        GatewayClient gateway = selectGateway(request);
        GatewayResponse gatewayResponse = gateway.charge(request);

        Payment payment = buildPaymentRecord(request, gatewayResponse, score);
        paymentRepository.save(payment);

        auditLogger.log(AuditEvent.PAYMENT_PROCESSED, payment);
        notifyAsync(payment);

        return PaymentResult.from(payment);
    }

    /**
     * Issues a full or partial refund for a completed payment.
     */
    public RefundResult processRefund(String paymentId, BigDecimal amount, String reason) {
        Payment payment = paymentRepository.findById(paymentId)
            .orElseThrow(() -> new PaymentNotFoundException("Payment not found: " + paymentId));

        if (!payment.isRefundable()) {
            throw new PaymentNotRefundableException(
                "Payment " + paymentId + " cannot be refunded (status=" + payment.getStatus() + ")");
        }

        BigDecimal refundAmount = (amount != null) ? amount : payment.getAmount();
        if (refundAmount.compareTo(payment.getAmount()) > 0) {
            throw new InvalidRefundAmountException(
                "Refund amount " + refundAmount + " exceeds original " + payment.getAmount());
        }

        GatewayClient gateway = gatewayClients.get(payment.getGatewayId());
        GatewayResponse refundResponse = gateway.refund(payment.getGatewayTransactionId(), refundAmount);

        Refund refund = Refund.builder()
            .id(UUID.randomUUID().toString())
            .paymentId(paymentId)
            .amount(refundAmount)
            .reason(reason)
            .gatewayRefundId(refundResponse.getTransactionId())
            .status(RefundStatus.fromGatewayStatus(refundResponse.getStatus()))
            .createdAt(Instant.now())
            .build();

        paymentRepository.saveRefund(refund);
        auditLogger.log(AuditEvent.REFUND_PROCESSED, refund);

        return RefundResult.from(refund);
    }

    /**
     * Reconciles daily transactions against gateway settlement reports.
     */
    public ReconciliationReport reconcile(LocalDateTime date) {
        List<Payment> dbPayments = paymentRepository.findByDate(date);
        Map<String, List<Payment>> byGateway = dbPayments.stream()
            .collect(Collectors.groupingBy(Payment::getGatewayId));

        List<ReconciliationEntry> entries = new ArrayList<>();
        List<ReconciliationDiscrepancy> discrepancies = new ArrayList<>();

        for (Map.Entry<String, List<Payment>> entry : byGateway.entrySet()) {
            String gatewayId = entry.getKey();
            List<Payment> payments = entry.getValue();

            GatewayClient gateway = gatewayClients.get(gatewayId);
            List<GatewaySettlementRecord> settlementRecords =
                gateway.fetchSettlementReport(date.toLocalDate());

            Map<String, GatewaySettlementRecord> settlementMap = settlementRecords.stream()
                .collect(Collectors.toMap(
                    GatewaySettlementRecord::getTransactionId,
                    r -> r
                ));

            for (Payment payment : payments) {
                GatewaySettlementRecord record = settlementMap.get(payment.getGatewayTransactionId());

                if (record == null) {
                    discrepancies.add(ReconciliationDiscrepancy.missing(payment));
                } else if (record.getAmount().compareTo(payment.getAmount()) != 0) {
                    discrepancies.add(ReconciliationDiscrepancy.amountMismatch(payment, record));
                } else {
                    entries.add(ReconciliationEntry.matched(payment, record));
                }
            }
        }

        ReconciliationReport report = ReconciliationReport.builder()
            .date(date)
            .totalPayments(dbPayments.size())
            .matchedCount(entries.size())
            .discrepancyCount(discrepancies.size())
            .entries(entries)
            .discrepancies(discrepancies)
            .generatedAt(Instant.now())
            .build();

        log.info("Reconciliation complete for {}: matched={} discrepancies={}",
            date, entries.size(), discrepancies.size());

        return report;
    }

    @Cacheable(value = "customerPaymentHistory", key = "#customerId")
    public List<PaymentSummary> getPaymentHistory(String customerId, int page, int size) {
        return paymentRepository.findByCustomerId(customerId,
                org.springframework.data.domain.PageRequest.of(page, size))
            .stream()
            .map(PaymentSummary::from)
            .collect(Collectors.toList());
    }

    // -----------------------------------------------------------------------
    // Gateway routing
    // -----------------------------------------------------------------------

    private GatewayClient selectGateway(PaymentRequest request) {
        String currency = request.getCurrency();
        BigDecimal amount = request.getAmount();
        String country = request.getBillingAddress().getCountryCode();

        // Route European cards to Stripe, US high-value to Braintree, rest to PayPal
        if (isEuropeanCountry(country)) {
            return gatewayClients.computeIfAbsent("stripe",
                id -> new StripeGatewayClient(STRIPE_SECRET_KEY, gatewayConfig));
        } else if ("USD".equals(currency) && amount.compareTo(new BigDecimal("5000")) >= 0) {
            return gatewayClients.computeIfAbsent("braintree",
                id -> new BraintreeGatewayClient(gatewayConfig));
        } else {
            return gatewayClients.computeIfAbsent("paypal",
                id -> new PayPalGatewayClient(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, gatewayConfig));
        }
    }

    private boolean isEuropeanCountry(String code) {
        Set<String> EU = Set.of("DE","FR","ES","IT","NL","BE","AT","PT","SE","DK",
            "FI","PL","CZ","RO","HU","SK","BG","HR","SI","EE","LV","LT","LU","MT","CY","IE","GR");
        return EU.contains(code);
    }

    // -----------------------------------------------------------------------
    // Encryption utilities (AES-256-GCM)
    // -----------------------------------------------------------------------

    public String encryptCardData(String plaintext, byte[] keyBytes) throws Exception {
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] combined = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(cipherText, 0, combined, iv.length, cipherText.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public String decryptCardData(String ciphertext, byte[] keyBytes) throws Exception {
        byte[] combined = Base64.getDecoder().decode(ciphertext);
        byte[] iv = Arrays.copyOfRange(combined, 0, GCM_IV_LENGTH);
        byte[] cipherBytes = Arrays.copyOfRange(combined, GCM_IV_LENGTH, combined.length);

        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance(AES_GCM_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, iv));

        return new String(cipher.doFinal(cipherBytes), StandardCharsets.UTF_8);
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    private void validateRequest(PaymentRequest request) {
        Objects.requireNonNull(request, "PaymentRequest must not be null");
        Objects.requireNonNull(request.getCustomerId(), "CustomerId required");
        Objects.requireNonNull(request.getAmount(), "Amount required");

        if (request.getAmount().compareTo(BigDecimal.ZERO) <= 0) {
            throw new InvalidPaymentRequestException("Amount must be positive");
        }
        if (request.getCurrency() == null || request.getCurrency().length() != 3) {
            throw new InvalidPaymentRequestException("Invalid currency code");
        }

        CardData card = request.getCardData();
        if (!isValidLuhn(card.getNumber())) {
            throw new InvalidCardException("Card number failed Luhn check");
        }
        if (card.isExpired()) {
            throw new InvalidCardException("Card is expired");
        }
    }

    private boolean isValidLuhn(String number) {
        int sum = 0;
        boolean alternate = false;
        for (int i = number.length() - 1; i >= 0; i--) {
            int n = Character.getNumericValue(number.charAt(i));
            if (alternate) {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            alternate = !alternate;
        }
        return sum % 10 == 0;
    }

    // -----------------------------------------------------------------------
    // Builders & helpers
    // -----------------------------------------------------------------------

    private Payment buildPaymentRecord(PaymentRequest req, GatewayResponse resp, FraudScore score) {
        return Payment.builder()
            .id(UUID.randomUUID().toString())
            .customerId(req.getCustomerId())
            .cardToken(req.getCardToken())
            .amount(req.getAmount())
            .currency(req.getCurrency())
            .status(PaymentStatus.fromGatewayStatus(resp.getStatus()))
            .gatewayId(resp.getGatewayId())
            .gatewayTransactionId(resp.getTransactionId())
            .fraudScore(score.getValue())
            .metadata(req.getMetadata())
            .createdAt(Instant.now())
            .build();
    }

    @Async
    private void notifyAsync(Payment payment) {
        asyncPool.submit(() -> {
            try {
                // Placeholder: emit to Kafka / SNS
                log.debug("Async notification sent for paymentId={}", payment.getId());
            } catch (Exception e) {
                log.error("Failed to send async notification for paymentId={}", payment.getId(), e);
            }
        });
    }
}
