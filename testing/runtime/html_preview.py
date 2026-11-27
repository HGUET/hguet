"""Generate portable HTML from independent SDK transactions; validate passive markup."""
import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import subprocess
import tempfile

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")


class PassiveMarkup(HTMLParser):
    allowed = {
        "html", "head", "meta", "title", "style", "body", "main", "header", "section",
        "footer", "p", "h1", "h2", "h3", "h4", "nav", "a", "dl", "dt", "dd", "div",
        "span", "table", "thead", "tbody", "tr", "th", "td", "article", "strong",
        "small", "code", "ul", "li", "details", "summary",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = set()
        self.links = []
        self.csp = None

    def handle_starttag(self, tag, attrs):
        assert tag in self.allowed, tag
        values = dict(attrs)
        for key, value in attrs:
            assert not key.startswith("on"), key
            assert key not in {"src", "srcset", "action", "formaction", "style", "ping"}, key
            if key == "href":
                assert tag == "a" and value.startswith("#"), value
                self.links.append(value[1:])
            if key == "id":
                assert value not in self.ids, value
                self.ids.add(value)
        if tag == "meta" and values.get("http-equiv", "").lower() == "content-security-policy":
            self.csp = values["content"]

    def verify(self):
        assert self.csp and "default-src 'none'" in self.csp
        assert {"analysis", "limitations", "evidence"} <= self.ids
        assert set(self.links) <= self.ids, set(self.links) - self.ids


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--hguet", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    binary = args.hguet.resolve()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    report_dir = args.out.parent / "html-reports"
    report_dir.mkdir(exist_ok=True)
    cases = []

    payer = Keypair()
    receiver, source, delegate = (Pubkey.new_unique() for _ in range(3))
    block = Hash.new_unique()

    def tx(amount, approval=False):
        instructions = [transfer(TransferParams(from_pubkey=payer.pubkey(),
                                              to_pubkey=receiver, lamports=amount))]
        if approval:
            instructions.append(Instruction(TOKEN, b"\x04" + (99).to_bytes(8, "little"),
                [AccountMeta(source, False, True), AccountMeta(delegate, False, False),
                 AccountMeta(payer.pubkey(), True, False)]))
        message = Message.new_with_blockhash(instructions, payer.pubkey(), block)
        return bytes(Transaction([payer], message, block))

    def run(arguments, data=None):
        return subprocess.run([str(binary), *arguments], input=data, capture_output=True, timeout=20)

    def record(name):
        cases.append({"case":name,"comparison":"PASS"})
        args.out.write_text(json.dumps({"cases":cases,"acceptance":"INCOMPLETE"},indent=2))

    before, after = tx(100), tx(1000, True)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "before.bin"
        path.write_bytes(before)
        for command, inputs, title, expected in [
            ("programs", ["-"], "Program Intelligence", ["DECODED_DECLARATION", "system"]),
            ("flow", ["-"], "Asset Flow Intelligence", ["Declared asset movements", "1000", str(receiver)]),
            ("authority", ["-"], "Authority Intelligence", ["set_delegate", str(delegate), "99"]),
            ("diff", [str(path), "-"], "Semantic Transaction Diff", ["MESSAGE_CHANGED", "asset_movement", "authority_change"]),
        ]:
            arguments = [command, *inputs, "--offline"]
            default = run(arguments, after)
            explicit = run([*arguments, "--json"], after)
            assert default.returncode == explicit.returncode == 0
            assert json.loads(default.stdout) == json.loads(explicit.stdout)
            p = run([*arguments, "--html"], after)
            assert p.returncode == 0, p.stderr
            html = p.stdout.decode("utf-8")
            assert html.startswith("<!doctype html>")
            assert title in html and "NOT_AUTHORIZED" in html
            assert all(value in html for value in expected), expected
            assert "<script" not in html.lower()
            markup = PassiveMarkup()
            markup.feed(html)
            markup.close()
            markup.verify()
            assert len(markup.links) > 3, command
            (report_dir / f"{command}.html").write_text(html, encoding="utf-8")
            record(command + "_standalone_html")

        for command, inputs in [("programs", ["-"]), ("flow", ["-"]),
                                ("authority", ["-"]), ("diff", [str(path), "-"])]:
            p = run([command, *inputs, "--offline", "--html", "--json"], after)
            assert p.returncode == 40
            assert json.loads(p.stdout)["signing_authorization"] == "NOT_AUTHORIZED"
        record("format_conflicts_preserve_error_contract")

        p = run(["flow", "-", "--offline", "--html"], b"\xff")
        assert p.returncode == 40 and json.loads(p.stdout)["kind"] == "hguet_flow_error"
        record("invalid_wire_is_not_a_successful_html_report")

    args.out.write_text(json.dumps({"cases":cases,"mandatory_count":6,
                                    "passed_count":len(cases),"acceptance":"PASS"},indent=2))
    print("PASS: 6 standalone HTML CLI comparisons; 4 actual generated reports preserved")


if __name__ == "__main__":
    main()
