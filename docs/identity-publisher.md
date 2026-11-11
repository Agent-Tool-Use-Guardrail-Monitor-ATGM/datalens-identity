# Identity publisher

Step **3.8.4.4.2** adds a separate Python process for delivering committed
identity outbox events to RabbitMQ. The messaging repository owns the
`identity` vhost, `identity.events.v1` exchange and bindings.

## Start the process

1. Apply the Keycloak outbox migration. The provider currently ships in the
   disposable test image. Hosted activation is a later step.
2. As the PostgreSQL administrator, create a dedicated LOGIN role. Use
   `\password` to set its password through an interactive prompt.

   ```sql
   CREATE ROLE identity_publisher LOGIN;
   \password identity_publisher
   ```

3. As the identity schema owner, run `psql -f tools/grant_publisher.sql` against
   the identity database. The script grants access to the needed outbox
   columns and the bounded cleanup function.
4. Install `requirements-publisher.txt` in a Python 3.12 virtual environment.
   Set these environment variables through your shell or secret manager, then
   run `python tools/identity_publisher.py`.

| Variable | Value |
| --- | --- |
| `IDENTITY_PUBLISHER_DB_DSN` | PostgreSQL DSN for the scoped role. Use `sslmode=verify-full` for hosted connections. |
| `IDENTITY_PUBLISHER_AMQP_URL` | URL with the `identity-publisher` RabbitMQ credentials and `/identity` vhost. Use `amqps://` for hosted connections. URL-encode credentials. |
| `IDENTITY_PUBLISHER_ISSUER` | Exact realm issuer used in outbox events, including the realm path. |

Plaintext AMQP is allowed for loopback and the local Compose hostname
`rabbitmq`. AMQPS verifies the server certificate and hostname.
Start the local broker using the messaging repository's guide.

## Delivery and recovery

- PostgreSQL leases a pending row for two minutes with a unique claim token.
  The claim statement commits before contacting RabbitMQ.
- The publisher validates the stored envelope against the configured issuer,
  passively checks the exchange and sends a persistent message with mandatory
  routing. The stored event ID becomes the AMQP message ID.
- A broker confirm permits the publisher to mark the row published if its
  claim token still matches. Unconfirmed sends retry after five seconds. If
  the process exits before recording a confirm, the next attempt uses the
  same event ID after the lease expires. Consumers must tolerate duplicates
  and out-of-order events.
- Invalid stored envelopes stay pending for inspection and are retried after
  five minutes. Warnings include neither event bodies nor connection secrets.
- Every 30 seconds, the process checks up to 1,000 pending rows. It warns when
  the count reaches 1,000 or the oldest has waited five minutes. The same
  pass removes up to 1,000 confirmed rows older than seven days. Pending
  rows survive cleanup.

The runtime test uses disposable PostgreSQL and the merged messaging
topology. It covers outage recovery, claim fencing, stable IDs on redelivery,
scoped database access and published-row retention. Coordinated transport
acceptance across services is step 3.8.4.5.

[RabbitMQ publisher confirms](https://www.rabbitmq.com/docs/confirms)
