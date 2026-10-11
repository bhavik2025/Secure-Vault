import math
import string

import pytest

from apps.policies.enforcement import BuiltinPolicy, check_password_rules
from apps.vault import passwords
from apps.vault.passwords import AMBIGUOUS, SYMBOLS, estimate_strength, generate_password


# --- generator ---------------------------------------------------------------------------------

@pytest.mark.parametrize("length", [8, 12, 20, 64, 128])
def test_generates_the_requested_length(length):
    assert len(generate_password(length)) == length


def test_every_selected_class_is_always_present():
    for _ in range(300):
        pw = generate_password(8)  # the tightest case: 4 classes in 8 characters
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_only_selected_classes_are_used():
    pw = generate_password(64, lowercase=False, uppercase=False, digits=True, symbols=False)
    assert pw.isdigit()
    assert set(generate_password(64, symbols=False)) <= set(string.ascii_letters + string.digits)


def test_ambiguous_characters_can_be_excluded():
    for _ in range(100):
        assert not (set(generate_password(40, exclude_ambiguous=True)) & AMBIGUOUS)


def test_output_is_random_not_repeating():
    assert len({generate_password(20) for _ in range(2000)}) == 2000


def test_uses_the_secrets_module_not_random(monkeypatch):
    calls = []
    real = passwords.secrets.choice
    monkeypatch.setattr(passwords.secrets, "choice", lambda seq: (calls.append(1), real(seq))[1])
    generate_password(16)
    assert len(calls) == 16


def test_character_distribution_is_roughly_uniform():
    counts = {}
    for _ in range(400):
        for c in generate_password(50, uppercase=False, symbols=False):
            counts[c] = counts.get(c, 0) + 1
    # lowercase+digits = 36 symbols; ~20000 draws -> expect ~555 each (well within 25%)
    assert len(counts) == 36 and max(counts.values()) < 1.25 * 20000 / 36 * 1.2 and min(counts.values()) > 0.6 * 20000 / 36


@pytest.mark.parametrize("kwargs", [{"length": 7}, {"length": 129}, {"lowercase": False, "uppercase": False, "digits": False, "symbols": False}])
def test_invalid_generator_arguments_are_rejected(kwargs):
    with pytest.raises(ValueError):
        generate_password(**{"length": 20, **kwargs})


def test_generated_passwords_satisfy_a_typical_policy():
    policy = BuiltinPolicy(min_length=12, require_symbols=True)
    assert all(not check_password_rules(generate_password(12), policy) for _ in range(200))


# --- strength / entropy ------------------------------------------------------------------------------

def test_random_generated_password_is_estimated_close_to_theoretical_entropy():
    pw = generate_password(24)
    bits = estimate_strength(pw).bits
    assert 24 * math.log2(94) * 0.7 < bits <= 24 * math.log2(95) + 0.1
    assert estimate_strength(pw).label in ("STRONG", "VERY_STRONG")


@pytest.mark.parametrize("pw", ["password", "123456", "qwerty", "letmein", "Password1"])
def test_common_passwords_are_very_weak(pw):
    s = estimate_strength(pw)
    assert s.bits <= 14.0 and s.label == "VERY_WEAK" and "common_password" in s.issues


def test_repeated_and_sequential_characters_are_penalized():
    assert estimate_strength("aaaaaaaaaaaa").bits < estimate_strength("kqzfjwxvbnmt").bits
    s = estimate_strength("abcdefgh1234")
    assert "repeated_or_sequential_characters" in s.issues and s.label in ("VERY_WEAK", "WEAK")


def test_longer_and_richer_is_stronger():
    short = estimate_strength("Ab3$").bits
    medium = estimate_strength("Ab3$Zq9!").bits
    long_ = estimate_strength("Ab3$Zq9!Kp2#Wm7&").bits
    assert short < medium < long_
    assert estimate_strength("kqzfjwxv").bits < estimate_strength("kqzFjw3x").bits < estimate_strength("kqzFjw3$").bits


def test_labels_follow_thresholds():
    assert passwords.label_for_bits(10) == "VERY_WEAK"
    assert passwords.label_for_bits(30) == "WEAK"
    assert passwords.label_for_bits(50) == "FAIR"
    assert passwords.label_for_bits(70) == "STRONG"
    assert passwords.label_for_bits(120) == "VERY_STRONG"


@pytest.mark.parametrize("pw", ["", "a", "éèêëïöü", "x" * 500])
def test_estimator_handles_edge_inputs(pw):
    s = estimate_strength(pw)
    assert s.bits >= 0 and s.label
