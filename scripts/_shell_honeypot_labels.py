"""Reviewed behavior labels for issue #154, independent of replay severity.

KISS reviewed these narrow rules against the issue's examples. Routine queries
and literal output are benign only with complete, understood syntax. Writing
an SSH public key to authorized_keys, explicitly disabling security controls,
and downloading then launching the same absolute path are malicious in this
attack collection. These are behavior labels, not claims about operator intent
or successful execution. Unknown syntax stays unknown; replay scores cannot
override these decisions. References identify the design supporting each rule.
"""

import posixpath
import re
from collections.abc import Sequence
from dataclasses import dataclass

from _ingest import SHELL, Command, _word


@dataclass(frozen=True)
class LabelDecision:
    """A behavior label, stable explanation, and supporting review references."""

    label: str
    reason: str
    references: tuple[str, ...] = ()


_REFERENCE = "https://github.com/davidwagner/malcmds/issues/154"
_UNKNOWN = LabelDecision("unknown", "uncovered-or-incomplete")
_LITERAL = {"command_name", "word", "string", "string_content", "raw_string",
            "ansi_c_string", "concatenation", "number"}
_STRUCTURE = {"program", "list", "command", "redirected_statement", "file_redirect", "comment"}
# KISS reviewed these frequent complete inputs from the pinned release. Each
# reads hardware/process information or formats that output. The awk programs
# only print fields: accepting arbitrary awk or substitutions would also admit
# command execution. Exact matching keeps those additional semantics excluded.
_READ_ONLY_INPUTS = {
    "cat /proc/cpuinfo | grep name | wc -l",
    "cat /proc/cpuinfo | grep model | grep name | wc -l",
    "lscpu | grep Model",
    "df -h | head -n 2 | awk 'FNR == 2 {print $2;}'",
    "ls -lh $(which ls)",
    "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'",
    "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'",
    "cat /proc/cpuinfo | grep name | cut -f2 -d: | uniq -c ; uname -a",
    "cat /proc/cpuinfo|grep name|cut -f2 -d':'|uniq -c ; uname -a",
    "ps | grep '[Mm]iner'",
    "ps -ef | grep '[Mm]iner'",
    "echo Hi | cat -n",
}


def _decision(label: str, rule: str) -> LabelDecision:
    return LabelDecision(label, rule, (_REFERENCE,))


def _nodes(root):
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(reversed(node.named_children))


def _literal(node) -> bool:
    return all(part.type in _LITERAL and not (
        part.type == "word" and re.search(rb"(?<!\\)[*?\[]", part.text)
    ) for part in _nodes(node))


def _program(path: str) -> str:
    # An executable named /tmp/uname is not necessarily the system utility.
    if "/" not in path or posixpath.dirname(path) in {"/bin", "/usr/bin", "/sbin", "/usr/sbin"}:
        return posixpath.basename(path)
    return ""


def _routine(program: str, args: list[str]) -> bool:
    if program == "echo":
        return True
    if program in {"pwd", "whoami", "id", "arch", "hostname", "uptime", "true", "false",
                   "w", "top", "lscpu", "nproc", "ifconfig"}:
        return not args
    if program == "which":
        return args == ["ls"]
    if program == "crontab":
        return args == ["-l"]
    if program == "uname":
        return all(re.fullmatch(r"-[asnrvmpio]+", arg) is not None for arg in args)
    if program == "ls":
        return all(re.fullmatch(r"-[alhd]+", arg) is not None for arg in args)
    if program == "cat":
        return bool(args) and all(arg in {
            "/proc/cpuinfo", "/proc/meminfo", "/proc/version", "/etc/os-release",
            "/etc/issue", "/etc/hostname",
        } for arg in args)
    return False


def _security_disable(program: str, args: list[str]) -> bool:
    return (
        (program == "setenforce" and args in (["0"], ["Permissive"], ["permissive"]))
        or (program == "ufw" and args in (["disable"], ["--force", "disable"]))
        or (program in {"iptables", "ip6tables"} and args in (["-F"], ["--flush"]))
        or (program == "systemctl" and len(args) == 2
            and args[0] in {"stop", "disable", "mask"}
            and args[1].removesuffix(".service") in {"firewalld", "ufw", "auditd", "apparmor"})
    )


def _download_path(program: str, args: list[str]) -> str | None:
    # Accept just one URL and one explicit output option. Other options can
    # change wget/curl semantics, so extending this rule requires review.
    if program not in {"wget", "curl"} or len(args) != 3:
        return None
    option = "-O" if program == "wget" else "-o"
    if args[0] == option:
        path, url = args[1:]
    elif args[1] == option:
        url, path = args[0], args[2]
    else:
        return None
    if path.startswith("/") and re.match(r"https?://[^/\s]+", url):
        return path
    return None


def _command_redirects(node):
    # tree-sitter can wrap `a && echo key >>file` as a redirected list, even
    # though Bash redirects only its final command. Walk the final list child
    # to associate that redirect with echo and leave a's behavior unchanged.
    redirects = [child for child in node.named_children if child.type == "file_redirect"]
    current = node
    while current.parent.type == "list" and current.parent.named_children[-1] == current:
        current = current.parent
    if current.parent.type == "redirected_statement":
        redirects.extend(child for child in current.parent.named_children if child.type == "file_redirect")
    return redirects


def classify_input(text: str, commands: Sequence[Command]) -> tuple[LabelDecision, list[LabelDecision]]:
    """Label full shell syntax and its parsed invocations, preserving their order.

    Apart from explicitly reviewed complete inputs, rules exclude functions,
    loops, substitutions, pipelines and assignments from benign decisions. Children inside unresolved
    structures remain unknown. Downloads must immediately precede execution,
    use the same absolute path and have no redirections; unrelated children
    retain their own decisions. An empty input is never vacuously benign.
    """
    decisions = [_UNKNOWN for _ in commands]
    if not text.strip():
        return LabelDecision("unknown", "empty-input"), decisions
    if text.strip(" \t\n") in _READ_ONLY_INPUTS and commands:
        decision = _decision("benign", "reviewed-read-only-input")
        return decision, [decision for _ in commands]
    root = SHELL.parse(text.encode("utf-8", "replace")).root_node
    nodes = list(_nodes(root))
    if root.has_error:
        return LabelDecision("unknown", "incomplete-syntax"), decisions
    understood = all(node.type in _LITERAL | _STRUCTURE for node in nodes)
    invocations = [node for node in nodes if node.type == "command"]
    if len(invocations) != len(commands):
        return _UNKNOWN, decisions
    plain = []
    for index, (node, command) in enumerate(zip(invocations, commands)):
        ancestor = node.parent
        safe_context = True
        while ancestor is not None:
            if ancestor.type not in _STRUCTURE:
                safe_context = False
            ancestor = ancestor.parent
        name = node.child_by_field_name("name")
        arguments = [child for i, child in enumerate(node.children)
                     if node.field_name_for_child(i) == "argument"]
        words = [_word(name), *map(_word, arguments)] if name else []
        if not safe_context or any(child.type == "variable_assignment" for child in node.named_children) or words != [command.pgm, *command.args] or not all(_literal(part) for part in [name, *arguments] if part):
            plain.append(False)
            continue
        redirects = _command_redirects(node)
        plain.append(not redirects)
        program = _program(command.pgm)
        if _security_disable(program, command.args):
            decisions[index] = _decision("malicious", "disable-security")
        elif program == "echo" and re.match(r"ssh-(?:rsa|ed25519) [A-Za-z0-9+/=]+(?:\s|$)", " ".join(command.args)):
            # Additional redirects can replace or duplicate stdout. Restrict
            # this rule to one explicit stdout output, preserving its order.
            for redirect in redirects if len(redirects) == 1 else []:
                target = redirect.child_by_field_name("destination")
                descriptor = redirect.child_by_field_name("descriptor")
                if ((descriptor is None or descriptor.text == b"1") and target and _literal(target)
                    and re.search(r"(?:^|/)\.ssh/authorized_keys$", _word(target))
                    and any(child.type in {">", ">>"} for child in redirect.children)):
                    decisions[index] = _decision("malicious", "install-ssh-key")
        elif not redirects and _routine(program, command.args):
            decisions[index] = _decision("benign", "routine-literal-command")
    for index in range(len(commands) - 1):
        download, launch = commands[index:index + 2]
        path = _download_path(_program(download.pgm), download.args)
        separator = text.encode("utf-8", "replace")[invocations[index].end_byte:invocations[index + 1].start_byte]
        if path and re.fullmatch(rb"\s*(?:;|&&|\|\|)?\s*", separator) and plain[index] and plain[index + 1] and (
            launch.pgm == path or (_program(launch.pgm) in {"sh", "bash", "dash"} and launch.args == [path])
        ):
            decisions[index] = decisions[index + 1] = _decision("malicious", "download-and-execute")
    harmful = next((decision for decision in decisions if decision.label == "malicious"), None)
    if harmful:
        return harmful, decisions
    if understood and decisions and not any(node.type == "file_redirect" for node in nodes) and all(decision.label == "benign" for decision in decisions):
        return _decision("benign", "routine-complete-input"), decisions
    return _UNKNOWN, decisions
