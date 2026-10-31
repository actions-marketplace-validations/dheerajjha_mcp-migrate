"""R014 must distinguish MCP headers from ordinary browser EventSource reads."""
import pytest

from mcp_migrate.rules.r014_sse_resumability_removed import SSEResumabilityRemoved
from mcp_migrate.scan import load_project

MCP_CONTEXT = 'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\n'


@pytest.mark.parametrize("header", [
    "Mcp-Session-Id", "MCP-Protocol-Version", "Mcp-Method", "mcp-name",
])
def test_typescript_header_with_hand_rolled_mcp_transport(tmp_path, header):
    (tmp_path / "server.ts").write_text(
        f'const context = req.headers.get("{header}");\n'
        'const cursor = req.headers.get("Last-Event-ID");\n'
    )
    findings = SSEResumabilityRemoved().check(load_project(tmp_path).for_language("typescript"))
    assert [(f.path.name, f.line) for f in findings] == [("server.ts", 2)]


@pytest.mark.parametrize("same_file_context", [False, True])
@pytest.mark.parametrize("header", ["last-event-id", "Last-Event-ID"])
@pytest.mark.parametrize("quote", ['"', "'", "`"])
@pytest.mark.parametrize("read", ["req.headers.get({key})", "req.headers[{key}]"])
def test_typescript_header_requires_same_file_mcp_context(
    tmp_path, same_file_context, header, quote, read,
):
    # An MCP server elsewhere in the project cannot qualify a browser route.
    (tmp_path / "server.ts").write_text(MCP_CONTEXT)
    source = "const cursor = " + read.format(key=f"{quote}{header}{quote}") + ";\n"
    (tmp_path / "routes.ts").write_text((MCP_CONTEXT if same_file_context else "") + source)

    findings = SSEResumabilityRemoved().check(load_project(tmp_path).for_language("typescript"))

    assert [(f.path.name, f.line) for f in findings] == (
        [("routes.ts", 2)] if same_file_context else []
    )
    if same_file_context:
        assert findings[0].snippet == source.strip()


def test_typescript_header_and_identifier_deduplication_and_order(tmp_path):
    source = (
        MCP_CONTEXT
        + 'const cursor = req.headers.get("Last-Event-ID");\n'
        + 'const lastEventId = req.headers["last-event-id"];\n'
        + 'replay(lastEventId);\n'
    )
    for name in ("one.ts", "two.ts"):
        (tmp_path / name).write_text(source)
    findings = SSEResumabilityRemoved().check(load_project(tmp_path).for_language("typescript"))
    assert [(f.path.name, f.line) for f in findings] == [
        (name, line) for name in ("one.ts", "two.ts") for line in (2, 3, 4)
    ]


@pytest.mark.parametrize("source", [
    '// const cursor = req.headers["last-event-id"];\n',
    '/* Legacy transport:\nreq.headers["last-event-id"]\nlastEventId\n*/\n',
    'const notice = "Last-Event-ID resumability was removed";\n',
    'const notice = "lastEventId is an old variable name";\n',
    'const cursor = req.headers["X-Last-Event-ID"];\n',
    'const cursor = req.headers["Last-Event-ID-Suffix"];\n',
])
def test_typescript_header_prose_and_unrelated_names_stay_silent(tmp_path, source):
    (tmp_path / "server.ts").write_text(MCP_CONTEXT + source)
    assert SSEResumabilityRemoved().check(load_project(tmp_path).for_language("typescript")) == []
