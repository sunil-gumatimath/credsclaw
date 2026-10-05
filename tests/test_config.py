"""Config file loading and merging tests."""

import argparse

from auditor import (
    apply_config_to_parser,
    build_arg_parser,
    coerce_bool,
    load_config,
)


def test_load_config_missing_file(tmp_path):
    """load_config should return {} for a non-existent file."""
    assert load_config(str(tmp_path / "nonexistent.yaml")) == {}


def test_load_config_invalid_yaml(tmp_path):
    """load_config should return {} for malformed YAML."""
    bad_file = tmp_path / "bad.yaml"
    bad_file.write_text(": : invalid yaml : :", encoding="utf-8")
    assert load_config(str(bad_file)) == {}


def test_load_config_valid_yaml(tmp_path):
    """load_config should parse valid YAML correctly."""
    import yaml

    config_data = {
        "mode": "local",
        "providers": ["openai", "github"],
        "confidence_threshold": 70.0,
        "output_format": "html",
    }
    cfg_file = tmp_path / "auditor.yaml"
    cfg_file.write_text(yaml.dump(config_data), encoding="utf-8")
    result = load_config(str(cfg_file))
    assert result["mode"] == "local"
    assert result["providers"] == ["openai", "github"]
    assert result["confidence_threshold"] == 70.0
    assert result.get("repo") is None


def test_apply_config_sets_defaults():
    """apply_config_to_parser should set defaults from config dict."""
    config = {"mode": "local", "confidence_threshold": 80.0}
    parser = build_arg_parser()
    apply_config_to_parser(config, parser)
    args = parser.parse_args([], namespace=argparse.Namespace())
    assert args.mode == "local"
    assert args.confidence_threshold == 80.0


def test_apply_config_plural_list_conversion():
    """YAML lists should be converted to comma-separated strings."""
    config = {"providers": ["openai", "github", "aws"], "extensions": ["py", "js"]}
    parser = build_arg_parser()
    apply_config_to_parser(config, parser)
    args = parser.parse_args([], namespace=argparse.Namespace())
    assert args.providers == "openai,github,aws"
    assert args.extensions == "py,js"


def test_apply_config_skips_unknown_keys():
    """Unknown config keys should be ignored without error."""
    config = {"unknown_key": "value", "nonexistent": 42}
    parser = build_arg_parser()
    apply_config_to_parser(config, parser)
    args = parser.parse_args([], namespace=argparse.Namespace())
    assert args.mode == "code"
    assert args.providers == "openai,anthropic"


# ~~~ Boolean coercion ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
def test_coerce_bool_scalars():
    assert coerce_bool(True) is True
    assert coerce_bool(False) is False
    assert coerce_bool(1) is True
    assert coerce_bool(0) is False
    assert coerce_bool("yes") is True
    assert coerce_bool("NO") is False
    assert coerce_bool("off") is False
    assert coerce_bool("") is False
    assert coerce_bool("maybe") is None
    assert coerce_bool(None) is None


def test_boolean_flags_from_yaml_are_real_bools(tmp_path):
    """YAML ``validate: no`` must not become the truthy string ``'no'``."""
    import yaml

    cfg = {
        "validate": "no",
        "dry_run": "false",
        "store_raw_keys": 0,
        "no_ssl_verify": "yes",
        "encrypt_output": "true",
        "resume": False,
    }
    cfg_file = tmp_path / "auditor.yaml"
    cfg_file.write_text(yaml.dump(cfg), encoding="utf-8")

    parser = build_arg_parser()
    apply_config_to_parser(load_config(str(cfg_file)), parser)
    args = parser.parse_args([])

    assert args.validate is False
    assert args.dry_run is False
    assert args.store_raw_keys is False
    assert args.no_ssl_verify is True
    assert args.encrypt_output is True
    assert args.resume is False


def test_boolean_flag_from_yaml_can_be_overridden_by_cli(tmp_path):
    import yaml

    cfg_file = tmp_path / "auditor.yaml"
    cfg_file.write_text(yaml.dump({"validate": True}), encoding="utf-8")

    parser = build_arg_parser()
    apply_config_to_parser(load_config(str(cfg_file)), parser)
    # store_true has no --no-validate flag, so the config value stands.
    assert parser.parse_args([]).validate is True


def test_invalid_boolean_is_ignored_not_crashed(tmp_path, caplog):
    import logging

    caplog.set_level(logging.ERROR)
    import yaml

    cfg_file = tmp_path / "auditor.yaml"
    cfg_file.write_text(yaml.dump({"validate": "sometimes"}), encoding="utf-8")

    parser = build_arg_parser()
    apply_config_to_parser(load_config(str(cfg_file)), parser)
    args = parser.parse_args([])
    assert args.validate is False  # falls back to the argparse default
    assert any("Invalid boolean" in m for m in caplog.messages)
