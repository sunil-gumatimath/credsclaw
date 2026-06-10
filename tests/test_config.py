"""Config file loading and merging tests."""

import argparse

from auditor import (
    load_config,
    apply_config_to_parser,
    build_arg_parser,
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
