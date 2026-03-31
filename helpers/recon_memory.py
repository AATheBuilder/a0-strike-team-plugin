import json
import os
from datetime import UTC, datetime
from typing import Any

from python.helpers.recon_paths import get_recon_workdir


SCHEMA_VERSION = 1


def _db_path() -> str:
    workdir = get_recon_workdir()
    directory = os.path.join(workdir, ".a0_data")
    os.makedirs(directory, exist_ok=True)
    return os.path.join(directory, "recon_memory.json")


def load_recon_memory() -> dict[str, Any]:
    path = _db_path()
    if not os.path.exists(path):
        return {
            "schema_version": SCHEMA_VERSION,
            "updated_at": None,
            "entities": [],
            "relations": [],
            "evidence": [],
        }
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    data.setdefault("schema_version", SCHEMA_VERSION)
    data.setdefault("updated_at", None)
    data.setdefault("entities", [])
    data.setdefault("relations", [])
    data.setdefault("evidence", [])
    return data


def save_recon_memory(data: dict[str, Any]) -> str:
    data["updated_at"] = datetime.now(UTC).isoformat()
    path = _db_path()
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True)
    return path


def persist_recon_surface_report(report: dict[str, Any]) -> dict[str, Any]:
    data = load_recon_memory()
    before_entities = len(data["entities"])
    before_relations = len(data["relations"])
    before_evidence = len(data["evidence"])

    target_type = "IPAddress" if report.get("target_kind") == "ip" else "Domain"
    target_value = report.get("normalized_target", "")
    target_entity = _upsert_entity(
        data,
        entity_type=target_type,
        value=target_value,
        properties={
            "source": "recon_surface",
            "mode": report.get("mode"),
            "last_seen": report.get("generated_at"),
        },
    )

    report_path = report.get("artifacts", {}).get("report_path")
    if report_path:
        _add_evidence(
            data,
            evidence_type="report",
            value=report_path,
            source="recon_surface",
            related_entities=[target_entity["id"]],
            metadata={"target": target_value},
        )

    for ip in report.get("dns", {}).get("ip_addresses", []):
        ip_entity = _upsert_entity(
            data,
            entity_type="IPAddress",
            value=ip,
            properties={"source": "recon_surface", "last_seen": report.get("generated_at")},
        )
        _upsert_relation(
            data,
            from_id=target_entity["id"],
            relation_type="RESOLVES_TO",
            to_id=ip_entity["id"],
            properties={"source": "recon_surface"},
        )

    for subdomain in report.get("subdomains", []):
        sub_entity = _upsert_entity(
            data,
            entity_type="Subdomain",
            value=subdomain,
            properties={"source": "recon_surface", "last_seen": report.get("generated_at")},
        )
        _upsert_relation(
            data,
            from_id=sub_entity["id"],
            relation_type="BELONGS_TO",
            to_id=target_entity["id"],
            properties={"source": "recon_surface"},
        )

    for item in report.get("http", []):
        url = item.get("final_url") or item.get("url")
        if not url:
            continue
        web_asset = _upsert_entity(
            data,
            entity_type="WebAsset",
            value=url,
            properties={
                "status": item.get("status"),
                "title": item.get("title"),
                "reachable": item.get("reachable"),
                "content_type": item.get("content_type"),
                "source": "recon_surface",
                "last_seen": report.get("generated_at"),
            },
        )
        _upsert_relation(
            data,
            from_id=target_entity["id"],
            relation_type="HOSTS",
            to_id=web_asset["id"],
            properties={"source": "recon_surface"},
        )

        service_value = _service_value_for_url(url)
        if service_value:
            service = _upsert_entity(
                data,
                entity_type="Service",
                value=service_value,
                properties={"source": "recon_surface", "last_seen": report.get("generated_at")},
            )
            _upsert_relation(
                data,
                from_id=target_entity["id"],
                relation_type="HOSTS",
                to_id=service["id"],
                properties={"source": "recon_surface"},
            )
            _upsert_relation(
                data,
                from_id=service["id"],
                relation_type="HOSTS",
                to_id=web_asset["id"],
                properties={"source": "recon_surface"},
            )

        for tech_value in (item.get("server"), item.get("x_powered_by")):
            if not tech_value:
                continue
            tech = _upsert_entity(
                data,
                entity_type="Technology",
                value=str(tech_value),
                properties={"source": "recon_surface", "last_seen": report.get("generated_at")},
            )
            _upsert_relation(
                data,
                from_id=web_asset["id"],
                relation_type="USES_TECH",
                to_id=tech["id"],
                properties={"source": "recon_surface"},
            )

        if item.get("tls"):
            _add_evidence(
                data,
                evidence_type="tls_metadata",
                value=url,
                source="recon_surface",
                related_entities=[target_entity["id"], web_asset["id"]],
                metadata=item.get("tls"),
            )

    for archived_url in report.get("archived_urls", []):
        evidence = _add_evidence(
            data,
            evidence_type="archived_url",
            value=archived_url,
            source="recon_surface",
            related_entities=[target_entity["id"]],
            metadata={"target": target_value},
        )
        _upsert_entity(
            data,
            entity_type="Evidence",
            value=archived_url,
            properties={"evidence_id": evidence["id"], "source": "recon_surface"},
        )

    path = save_recon_memory(data)
    return {
        "path": path,
        "entity_delta": len(data["entities"]) - before_entities,
        "relation_delta": len(data["relations"]) - before_relations,
        "evidence_delta": len(data["evidence"]) - before_evidence,
        "entity_total": len(data["entities"]),
        "relation_total": len(data["relations"]),
        "evidence_total": len(data["evidence"]),
    }


def query_recon_memory(
    *,
    entity_type: str = "",
    value_contains: str = "",
    relation_type: str = "",
    related_to: str = "",
    include_relations: bool = True,
    include_evidence: bool = True,
    limit: int = 25,
) -> dict[str, Any]:
    data = load_recon_memory()
    entities = data["entities"]
    relations = data["relations"]
    evidence = data["evidence"]

    filtered_entities = entities
    if entity_type:
        filtered_entities = [
            item for item in filtered_entities if item.get("entity_type", "").lower() == entity_type.lower()
        ]
    if value_contains:
        needle = value_contains.lower()
        filtered_entities = [
            item for item in filtered_entities if needle in str(item.get("value", "")).lower()
        ]

    if related_to:
        entity_ids = {
            item["id"]
            for item in entities
            if related_to.lower() in str(item.get("value", "")).lower()
        }
        linked_ids = set(entity_ids)
        for relation in relations:
            if relation["from_id"] in entity_ids:
                linked_ids.add(relation["to_id"])
            if relation["to_id"] in entity_ids:
                linked_ids.add(relation["from_id"])
        filtered_entities = [item for item in filtered_entities if item["id"] in linked_ids]

    filtered_entities = filtered_entities[: max(limit, 1)]
    entity_ids = {item["id"] for item in filtered_entities}

    filtered_relations = []
    if include_relations:
        filtered_relations = [
            item
            for item in relations
            if item["from_id"] in entity_ids or item["to_id"] in entity_ids
        ]
        if relation_type:
            filtered_relations = [
                item for item in filtered_relations if item.get("relation_type", "").lower() == relation_type.lower()
            ]

    filtered_evidence = []
    if include_evidence:
        filtered_evidence = [
            item
            for item in evidence
            if entity_ids.intersection(item.get("related_entities", []))
            or (value_contains and value_contains.lower() in str(item.get("value", "")).lower())
        ][: max(limit, 1)]

    return {
        "schema_version": data.get("schema_version"),
        "updated_at": data.get("updated_at"),
        "entity_count": len(filtered_entities),
        "relation_count": len(filtered_relations),
        "evidence_count": len(filtered_evidence),
        "entities": filtered_entities,
        "relations": filtered_relations,
        "evidence": filtered_evidence,
    }


def list_web_assets(related_to: str = "", limit: int = 25) -> list[str]:
    result = query_recon_memory(
        entity_type="WebAsset",
        related_to=related_to,
        include_relations=False,
        include_evidence=False,
        limit=limit,
    )
    return [str(item.get("value", "")) for item in result.get("entities", []) if item.get("value")]


def persist_web_surface_triage_report(report: dict[str, Any]) -> dict[str, Any]:
    data = load_recon_memory()
    before_entities = len(data["entities"])
    before_relations = len(data["relations"])
    before_evidence = len(data["evidence"])

    for target in report.get("targets", []):
        url = target.get("url")
        if not url:
            continue

        web_asset = _upsert_entity(
            data,
            entity_type="WebAsset",
            value=url,
            properties={
                "triaged_at": report.get("generated_at"),
                "source": "web_surface_triage",
                "title": target.get("title"),
                "status": target.get("status"),
                "reachable": target.get("reachable"),
            },
        )

        for path_item in target.get("interesting_paths", []):
            path_url = path_item.get("url")
            if not path_url:
                continue
            path_asset = _upsert_entity(
                data,
                entity_type="WebAsset",
                value=path_url,
                properties={
                    "triaged_at": report.get("generated_at"),
                    "source": "web_surface_triage",
                    "status": path_item.get("status"),
                    "reachable": path_item.get("reachable"),
                },
            )
            _upsert_relation(
                data,
                from_id=web_asset["id"],
                relation_type="DISCOVERED_FROM",
                to_id=path_asset["id"],
                properties={"source": "web_surface_triage"},
            )

        for hint in target.get("technology_hints", []):
            tech = _upsert_entity(
                data,
                entity_type="Technology",
                value=str(hint),
                properties={"source": "web_surface_triage", "last_seen": report.get("generated_at")},
            )
            _upsert_relation(
                data,
                from_id=web_asset["id"],
                relation_type="USES_TECH",
                to_id=tech["id"],
                properties={"source": "web_surface_triage"},
            )

        if target.get("login_indicators"):
            finding = _upsert_entity(
                data,
                entity_type="Finding",
                value=f"login-surface:{url}",
                properties={
                    "source": "web_surface_triage",
                    "kind": "login_surface",
                    "triaged_at": report.get("generated_at"),
                },
            )
            _upsert_relation(
                data,
                from_id=finding["id"],
                relation_type="EVIDENCED_BY",
                to_id=web_asset["id"],
                properties={"source": "web_surface_triage"},
            )

        _add_evidence(
            data,
            evidence_type="web_triage",
            value=url,
            source="web_surface_triage",
            related_entities=[web_asset["id"]],
            metadata={
                "title": target.get("title"),
                "status": target.get("status"),
                "forms_count": target.get("forms_count"),
                "interesting_paths": len(target.get("interesting_paths", [])),
            },
        )

    path = save_recon_memory(data)
    return {
        "path": path,
        "entity_delta": len(data["entities"]) - before_entities,
        "relation_delta": len(data["relations"]) - before_relations,
        "evidence_delta": len(data["evidence"]) - before_evidence,
        "entity_total": len(data["entities"]),
        "relation_total": len(data["relations"]),
        "evidence_total": len(data["evidence"]),
    }


def persist_vulnerability(
    *,
    target: str,
    cve_id: str = "",
    title: str,
    severity: str = "medium",
    description: str = "",
    proof: str = "",
) -> dict[str, Any]:
    """Store a discovered vulnerability in the recon memory."""
    data = load_recon_memory()
    target_info = _lookup_entity(data, target)
    if not target_info:
        # Create target if not exists
        from python.helpers.recon_scope import normalize_target, TargetInfo
        info = normalize_target(target)
        kind = getattr(info, "kind", "generic")
        etype = "IPAddress" if kind == "ip" else "Domain"
        target_info = _upsert_entity(data, entity_type=etype, value=target, properties={"source": "manual"})

    # Upsert CVE if provided
    cve_entity = None
    if cve_id:
        cve_entity = _upsert_entity(
            data,
            entity_type="CVE",
            value=cve_id.upper(),
            properties={"source": "manual"},
        )

    # Create Finding/Vulnerability entity
    vuln_entity = _upsert_entity(
        data,
        entity_type="Vulnerability",
        value=title,
        properties={
            "severity": severity.lower(),
            "description": description,
            "proof": proof,
            "source": "manual",
        },
    )

    # Link Vuln to Target
    _upsert_relation(
        data,
        from_id=target_info["id"],
        relation_type="VULNERABLE_TO",
        to_id=vuln_entity["id"],
        properties={"source": "manual"},
    )

    # Link Vuln to CVE
    if cve_entity:
        _upsert_relation(
            data,
            from_id=vuln_entity["id"],
            relation_type="IDENTIFIED_BY",
            to_id=cve_entity["id"],
            properties={"source": "manual"},
        )

    save_recon_memory(data)
    return vuln_entity


def persist_loot(
    *,
    target: str,
    kind: str,
    value: str,
    username: str = "",
    context: str = "",
) -> dict[str, Any]:
    """Store harvested credentials or sensitive data (loot) in the recon memory."""
    data = load_recon_memory()
    target_info = _lookup_entity(data, target)
    if not target_info:
        # Create target if not exists
        from python.helpers.recon_scope import normalize_target
        info = normalize_target(target)
        kind_t = getattr(info, "kind", "generic")
        etype = "IPAddress" if kind_t == "ip" else "Domain"
        target_info = _upsert_entity(data, entity_type=etype, value=target, properties={"source": "manual"})

    # Create Loot entity
    loot_val = f"{kind}:{username}" if username else f"{kind}:{value[:20]}..."
    loot_entity = _upsert_entity(
        data,
        entity_type="Loot",
        value=loot_val,
        properties={
            "kind": kind,
            "secret": value,  # NOTE: In a real prod env, this should be encrypted
            "username": username,
            "context": context,
            "source": "manual",
        },
    )

    # Link Loot to Target
    _upsert_relation(
        data,
        from_id=target_info["id"],
        relation_type="CONTAINS_LOOT",
        to_id=loot_entity["id"],
        properties={"source": "manual"},
    )

    save_recon_memory(data)
    return loot_entity


def _lookup_entity(data: dict[str, Any], value: str) -> dict[str, Any] | None:
    needle = str(value).strip().lower()
    for entity in data.get("entities", []):
        if str(entity.get("value", "")).lower() == needle:
            return entity
    return None


def _upsert_entity(data: dict[str, Any], *, entity_type: str, value: str, properties: dict[str, Any]) -> dict[str, Any]:
    key = _entity_key(entity_type, value)
    for entity in data["entities"]:
        if entity["id"] == key:
            entity["properties"].update({k: v for k, v in properties.items() if v is not None})
            entity["updated_at"] = datetime.now(UTC).isoformat()
            return entity

    entity = {
        "id": key,
        "entity_type": entity_type,
        "value": value,
        "properties": {k: v for k, v in properties.items() if v is not None},
        "created_at": datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    data["entities"].append(entity)
    return entity


def _upsert_relation(
    data: dict[str, Any],
    *,
    from_id: str,
    relation_type: str,
    to_id: str,
    properties: dict[str, Any],
) -> dict[str, Any]:
    key = f"{from_id}|{relation_type}|{to_id}"
    for relation in data["relations"]:
        if relation["id"] == key:
            relation["properties"].update({k: v for k, v in properties.items() if v is not None})
            relation["updated_at"] = datetime.now(UTC).isoformat()
            return relation

    relation = {
        "id": key,
        "from_id": from_id,
        "relation_type": relation_type,
        "to_id": to_id,
        "properties": {k: v for k, v in properties.items() if v is not None},
        "created_at": datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    data["relations"].append(relation)
    return relation


def _add_evidence(
    data: dict[str, Any],
    *,
    evidence_type: str,
    value: str,
    source: str,
    related_entities: list[str],
    metadata: dict[str, Any],
) -> dict[str, Any]:
    key = f"{evidence_type}|{value}"
    for evidence in data["evidence"]:
        if evidence["id"] == key:
            evidence["related_entities"] = sorted(set(evidence.get("related_entities", []) + related_entities))
            evidence["metadata"].update(metadata or {})
            evidence["updated_at"] = datetime.now(UTC).isoformat()
            return evidence

    evidence = {
        "id": key,
        "evidence_type": evidence_type,
        "value": value,
        "source": source,
        "related_entities": sorted(set(related_entities)),
        "metadata": metadata or {},
        "created_at": datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    data["evidence"].append(evidence)
    return evidence


def _entity_key(entity_type: str, value: str) -> str:
    return f"{entity_type}:{str(value).strip().lower()}"


def _service_value_for_url(url: str) -> str | None:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    hostname = parsed.hostname or parsed.netloc
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return f"{parsed.scheme}://{hostname}:{port}"
