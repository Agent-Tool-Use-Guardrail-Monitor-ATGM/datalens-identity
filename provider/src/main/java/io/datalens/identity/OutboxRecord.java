package io.datalens.identity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "dl_identity_outbox")
public class OutboxRecord {
    @Id
    @Column(name = "event_id", length = 36, nullable = false)
    public String eventId;

    @Column(name = "realm_id", length = 64, nullable = false)
    public String realmId;

    @Column(name = "subject", length = 255, nullable = false)
    public String subject;

    @Column(name = "payload", columnDefinition = "text", nullable = false)
    public String payload;

    @Column(name = "created_at_ms", nullable = false)
    public long createdAtMs;

    public OutboxRecord() {}
}
