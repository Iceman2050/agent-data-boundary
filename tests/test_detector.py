from agent_data_boundary import detector


def ids(text):
    return [f["rule_id"] for f in detector.scan_text(text)]


def test_rules_version_and_count():
    assert detector.PII_RULES_VERSION == "1.0.0"
    assert len(detector.RULE_IDS) == 15


def test_email_detected_for_real_domain():
    assert "PII-CONTACT-001" in ids("reach jane.doe@realmail.org please")


def test_example_email_suppressed_by_original_postfilter():
    # Carried over from the source pack: example/fictional values never fire.
    assert detector.scan_text("testa@example.com") == []


def test_luhn_valid_card_detected():
    assert "PII-PAY-001" in ids("card 4012888888881881 on file")


def test_luhn_invalid_card_rejected():
    assert "PII-PAY-001" not in ids("card 4012888888881882 on file")


def test_ssn_detected():
    assert "PII-ID-001" in ids("ssn 078-05-1120 recorded")


def test_private_ip_detected_public_ip_not():
    assert "PII-CONTACT-003" in ids("host 192.168.1.20 down")
    assert "PII-CONTACT-003" not in ids("host 8.8.8.8 down")


def test_aws_key_shape_detected():
    assert "PII-SECRET-001" in ids("key AKIAIOSFODNN7REALXYZ here")


def test_masking_never_leaks_full_value():
    text = "card 4012888888881881 on file"
    for f in detector.scan_text(text):
        assert "4012888888881881" not in f["excerpt"]
        assert "*" in f["excerpt"]


def test_clean_text_verdict_wording():
    assert detector.scan_text("nothing sensitive here") == []


def test_scan_record_anchors_to_store_and_record():
    out = detector.scan_record("conversations", "conversations:1",
                               "card 4012888888881881")
    assert out and out[0]["store"] == "conversations"
    assert out[0]["record_id"] == "conversations:1"
    assert out[0]["rules_version"] == "1.0.0"
