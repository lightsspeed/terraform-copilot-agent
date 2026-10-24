"""Basic scaffold verification tests for Milestone 1."""

import terraform_copilot_agent


def test_package_metadata() -> None:
    """Verify that package version and basic metadata are defined."""
    assert hasattr(terraform_copilot_agent, "__version__")
    assert terraform_copilot_agent.__version__ == "0.1.0"


def test_cli_entrypoint(capsys) -> None:
    """Verify that the CLI entrypoint placeholder runs without error."""
    terraform_copilot_agent.main()
    captured = capsys.readouterr()
    assert "Terraform Copilot Agent v0.1.0" in captured.out
