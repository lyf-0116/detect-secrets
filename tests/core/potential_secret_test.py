import pytest

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.potential_secret import UNKNOWN_RULE
from testing.factories import potential_secret_factory


@pytest.mark.parametrize(
    'a, b, is_equal',
    [
        (
            potential_secret_factory(line_number=1),
            potential_secret_factory(line_number=2),
            True,
        ),
        (
            potential_secret_factory(type='A'),
            potential_secret_factory(type='B'),
            False,
        ),
        (
            potential_secret_factory(secret='A'),
            potential_secret_factory(secret='B'),
            False,
        ),
        (
            potential_secret_factory(rule='ruleA'),
            potential_secret_factory(rule='ruleB'),
            False,
        ),
        (
            potential_secret_factory(rule='ruleA'),
            potential_secret_factory(rule='ruleA'),
            True,
        ),
    ],
)
def test_equality(a, b, is_equal):
    assert (a == b) is is_equal

    # As a sanity check that it works both ways
    assert (a != b) is not is_equal


def test_secret_storage():
    secret = potential_secret_factory(secret='secret')
    assert secret.secret_hash != 'secret'


def test_json():
    secret = potential_secret_factory(secret='blah')
    for value in secret.json().values():
        assert value != 'blah'


def test_json_includes_rule_when_present():
    secret = potential_secret_factory(rule='some-rule')
    assert secret.json()['rule'] == 'some-rule'


@pytest.mark.parametrize(
    'kwargs',
    (
        {
            'line_number': 0,
        },
        {
            'is_secret': True,
            'is_verified': False,
        },
    ),
)
def test_load_secret_from_dict(kwargs):
    secret = potential_secret_factory(**kwargs)
    new_secret = PotentialSecret.load_secret_from_dict(secret.json())

    assert new_secret.secret_hash == secret.secret_hash
    assert new_secret.type == secret.type
    assert new_secret.filename == secret.filename
    assert new_secret.secret_value is None


def test_load_secret_from_dict_marks_missing_rule_as_unknown():
    secret = potential_secret_factory()
    assert 'rule' not in secret.json()

    new_secret = PotentialSecret.load_secret_from_dict(secret.json())

    assert new_secret.rule == UNKNOWN_RULE


def test_load_secret_from_dict_preserves_rule():
    secret = potential_secret_factory(rule='some-rule')
    new_secret = PotentialSecret.load_secret_from_dict(secret.json())

    assert new_secret == secret
    assert new_secret.rule == 'some-rule'


def test_stringify():
    secret = potential_secret_factory(type='secret_type', secret='blah')
    assert str(secret) == (
        'Secret Type: secret_type\n'
        'Location:    filename:1\n'
    )
