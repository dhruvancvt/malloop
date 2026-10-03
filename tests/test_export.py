"""IOC CSV export: the verdict's nested IOC dict flattened to a SOC-ingestible (type,value) feed."""
import csv

from malloop.cli import write_iocs_csv


def test_write_iocs_csv_flattens_kinds(tmp_path):
    final = {"iocs": {"domains": ["evil.test", "c2.test"], "sha256": ["abc123"], "ips": []}}
    path = write_iocs_csv(tmp_path / "iocs.csv", final)
    rows = list(csv.reader(path.open(encoding="utf-8")))
    assert rows[0] == ["type", "value"]
    assert ["domains", "evil.test"] in rows
    assert ["sha256", "abc123"] in rows
    assert len(rows) == 1 + 3  # header + 3 values (empty "ips" contributes nothing)


def test_write_iocs_csv_handles_no_iocs(tmp_path):
    path = write_iocs_csv(tmp_path / "iocs.csv", {})
    rows = list(csv.reader(path.open(encoding="utf-8")))
    assert rows == [["type", "value"]]
