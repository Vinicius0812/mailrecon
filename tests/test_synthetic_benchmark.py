import socket

from mailrecon.benchmark import run_benchmark


def test_owned_fixture_benchmark_reproducible_and_offline(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('No network in benchmark')
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', forbidden)
    report = run_benchmark()
    assert report == run_benchmark()
    assert report['synthetic_only'] is True
    assert report['cases'] == report['expectation_matches'] == 21
    assert report['true_positives'] == 2
    assert report['false_positives'] == report['false_negatives'] == 0
    assert report['precision'] == 1
    assert all(row['consistent'] and row['priority'] == 0 for row in report['records'])
