import pytest
import os
import hashlib

from yara_generator.string_extractor import extract_strings, get_interesting_strings
from yara_generator.generator import calculate_hashes, generate_yara_rule

def test_extract_strings_ascii():
    data = b"Some random binary data \x00\x01\x02http://malicious.com\x00this is a test string"
    strings = extract_strings(data, min_length=6)
    assert "http://malicious.com" in strings
    assert "this is a test string" in strings

def test_extract_strings_utf16():
    # "http://example.com" in UTF-16LE
    data = b"h\x00t\x00t\x00p\x00:\x00/\x00/\x00e\x00x\x00a\x00m\x00p\x00l\x00e\x00.\x00c\x00o\x00m\x00"
    strings = extract_strings(data, min_length=6)
    assert "http://example.com" in strings

def test_get_interesting_strings():
    strings = {
        "random string that is boring",
        "http://evil.com/payload.exe",
        "admin@corp.local",
        "C:\\Windows\\System32\\cmd.exe",
        "CreateRemoteThread",
        "192.168.1.100",
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    }
    interesting = get_interesting_strings(strings)

    assert "http://evil.com/payload.exe" in interesting
    assert "admin@corp.local" in interesting
    assert "C:\\Windows\\System32\\cmd.exe" in interesting
    assert "CreateRemoteThread" in interesting
    assert "192.168.1.100" in interesting
    assert "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" in interesting
    assert "random string that is boring" not in interesting

def test_calculate_hashes():
    data = b"test data"
    hashes = calculate_hashes(data)

    assert hashes["md5"] == hashlib.md5(data).hexdigest()
    assert hashes["sha1"] == hashlib.sha1(data).hexdigest()
    assert hashes["sha256"] == hashlib.sha256(data).hexdigest()

def test_generate_yara_rule_basic():
    data = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"http://malware.local/drop.bin"
    rule = generate_yara_rule("TestRule", data, file_name="test.exe")

    # Check basics
    assert "rule TestRule" in rule
    assert 'filename = "test.exe"' in rule

    # Check string extraction and formatting
    assert '$s0 = "http://malware.local/drop.bin" ascii wide' in rule

    # Check conditions
    assert "uint16(0) == 0x5a4d" in rule  # MZ magic bytes condition

def test_generate_yara_rule_escaping():
    data = b'C:\\malware\\path.exe and "quoted string"'
    rule = generate_yara_rule("EscapeRule", data)

    # Assert proper escaping in YARA rule format
    assert 'C:\\\\malware\\\\path.exe' in rule
