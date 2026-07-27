from typosquat_hunter.permutations import (
    generate_omission_permutations,
    generate_repetition_permutations,
    generate_transposition_permutations,
    generate_substitution_permutations,
    get_all_permutations
)

def test_generate_omission_permutations():
    perms = generate_omission_permutations("test")
    assert "est" in perms
    assert "tst" in perms
    assert "tet" in perms
    assert "tes" in perms

def test_generate_repetition_permutations():
    perms = generate_repetition_permutations("test")
    assert "ttest" in perms
    assert "teest" in perms
    assert "tesst" in perms
    assert "testt" in perms

def test_generate_transposition_permutations():
    perms = generate_transposition_permutations("test")
    assert "etst" in perms
    assert "tset" in perms
    assert "tets" in perms

def test_generate_substitution_permutations():
    perms = generate_substitution_permutations("test")
    # 't' is near 'r', 'y', 'f', 'g', '5', '6'
    assert "rest" in perms
    # 'e' is near 'w', 'r', 's', 'd', '3', '4'
    assert "twst" in perms

def test_get_all_permutations():
    perms = get_all_permutations("test")
    assert "test" not in perms
    assert "est" in perms
    assert "ttest" in perms
    assert "etst" in perms
    assert "rest" in perms
