# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Syntactic unit-test for all the YARA-L detection rule files.

This script tokenizes and parses all the files with a ".yaral" extension located
in or under the current directory, using PLY (Python Lex & Yacc).

This should quickly identify most errors when creating or modifying a YARA-L
detection rule, without having to use the Chronicle Detection API.

For an even higher level of confidence that a YARA-L rule is correct, you can
run the script "evaluate_rules.py" which relies on the Chronicle Detection API,
so it's slower than this unit-test but also more authoritative.
"""

import pathlib
import pprint
import re
import unittest

from ply import lex
from ply import yacc


class Lexer(object):
  """Tokenize the text of a YARA-L detection rule with Lex.

  Note: PLY's Lex uses by default the re.VERBOSE flag, i.e. it ignores spaces in
  the regular-expressions below, to allow easier reading by people.
  """

  # PLY doesn't support multi-character literals, so other operators are defined
  # as tokens below.
  literals = "{}(),!"

  # Each of these tokens is defined by a regular-expression "t_XXX" below.
  # Most definitions are simple attributes, but definitions with non-default
  # logic are methods (regular-expression docstring + statements + "return t").
  tokens = ("MULTI_LINE_COMMENT", "SINGLE_LINE_COMMENT", "RULE_NAME",
            "META_LABEL", "EVENTS_LABEL", "MATCH_LABEL", "CONDITION_LABEL",
            "META_LINE", "VARIABLE_NAME", "VARIABLE_FIELD", "COUNTER", "STRING",
            "RAW_STRING", "REGEX", "NOCASE", "NUMBER", "TIME_WINDOW", "EQ",
            "NE", "GT", "GE", "LT", "LE", "NOT", "AND", "OR",
            "NET_IP_IN_RANGE_CIDR", "RE_REGEX")

  # Comments can appear anywhere in the rule.

  def t_MULTI_LINE_COMMENT(self, t):
    r"/\* [\s\S]*? \*/"  # "[\s\S]" matches any character including newlines.
    t.lexer.lineno += t.value.count("\n")
    return t

  t_SINGLE_LINE_COMMENT = r"//.*"  # "." matches any character except a newline.

  # High-level rule structure.

  t_RULE_NAME = r"rule \s+ \w+"
  t_META_LABEL = r"meta:"
  t_EVENTS_LABEL = r"events:"
  t_MATCH_LABEL = r"match:"
  t_CONDITION_LABEL = r"condition:"

  # Rule details.

  t_META_LINE = r'\w+ \s* = \s* "[^"\r\n]*"'  # Support both \n and \r\n.

  t_VARIABLE_NAME = r"\$ \w+"
  t_VARIABLE_FIELD = r"\. \w+"
  t_COUNTER = r"\# [\w]+"

  t_STRING = r'" [^"\r\n]* "'
  t_RAW_STRING = r"` [^`\r\n]* `"

  def t_REGEX(self, t):
    r"/ [^/\r\n]+ /"
    # Verify that these regular-expressions are valid.
    try:
      re.compile(t.value[1:-1])
      return t
    except re.error as e:
      raise RuntimeError(f"Regular expression {t.value} in line " +
                         f"{t.lexer.lineno} is invalid ({e.msg}).")

  t_NOCASE = r"nocase"

  t_NUMBER = r"\d+ (\. \d+)?"  # Non-negative integers and floats.
  t_TIME_WINDOW = r"over \s+ \d+ [smhd]"

  t_EQ = r"="
  t_NE = r"!="
  t_GT = r">"
  t_GE = r">="
  t_LT = r"<"
  t_LE = r"<="
  t_NOT = r"not"
  t_AND = r"and"
  t_OR = r"or"

  # Functions.

  t_NET_IP_IN_RANGE_CIDR = r"net\.ip_in_range_cidr"
  t_RE_REGEX = r"re\.regex"

  # Special non-token rules.

  t_ignore = " \t"  # Ignore (common) whitespaces.

  def t_newline(self, t):
    r"(\r\n|\n)+"  # Support both \n and \r\n.
    t.lexer.lineno += t.value.count("\n")

  def t_error(self, t):
    t.value = re.split(r"\s", t.value)[0]
    raise RuntimeError(
        f"Unrecognized token in line {t.lexer.lineno} ({t.value}).")


class Parser(object):
  """Parse the tokens of a YARA-L detection rule with Yacc."""

  tokens = Lexer.tokens

  # AND > OR, both are left-associative.
  precedence = (
      ("left", "OR"),
      ("left", "AND"),
  )

  # Valid UDM fields in variable specifications (the relations between different
  # levels are defined in the method "p_variable_fields" below).

  udm_nouns = ("principal", "src", "target", "intermediary", "observer",
               "about")

  udm_top_level_fields = udm_nouns + ("metadata", "security_result", "network")

  udm_dns_fields = ("id", "response", "opcode", "authoritative", "truncated",
                    "recursion_desired", "recursion_available", "response_code",
                    "questions")

  udm_dns_questions_fields = ("name", "type", "class")

  udm_file_fields = ("sha256", "md5", "sha1", "size", "full_path", "mime_type",
                     "file_metadata")

  udm_http_fields = ("method", "referral_url", "user_agent", "response_code")

  udm_metadata_fields = ("event_type", "product_name", "product_event_type")

  udm_network_fields = ("sent_bytes", "received_bytes", "session_duration",
                        "session_id", "community_id", "direction",
                        "ip_protocol", "application_protocol", "ftp", "email",
                        "dns", "dhcp", "http", "tls", "smtp")

  udm_noun_fields = ("hostname", "asset_id", "user", "group", "process",
                     "asset", "ip", "nat_ip", "port", "nat_port", "mac",
                     "administrative_domain", "namespace", "url", "file",
                     "email", "registry", "application", "platform",
                     "platform_version", "platform_patch_level", "cloud",
                     "location", "resource", "labels", "object_reference",
                     "investigation")

  udm_process_fields = ("pid", "parent_pid", "parent_process", "file",
                        "command_line", "product_specific_process_id",
                        "access_mask", "product_specific_parent_process_id")

  udm_registry_fields = ("registry_key", "registry_value_name",
                         "registry_value_data")

  # Valid enum values (checked in the method "check_enum_values" below).

  metadata_event_type_values = (
      "PROCESS_UNCATEGORIZED", "PROCESS_LAUNCH", "PROCESS_INJECTION",
      "PROCESS_PRIVILEGE_ESCALATION", "PROCESS_TERMINATION", "PROCESS_OPEN",
      "PROCESS_MODULE_LOAD", "REGISTRY_UNCATEGORIZED", "REGISTRY_CREATION",
      "REGISTRY_MODIFICATION", "REGISTRY_DELETION", "SETTING_UNCATEGORIZED",
      "SETTING_CREATION", "SETTING_MODIFICATION", "SETTING_DELETION",
      "FILE_UNCATEGORIZED", "FILE_CREATION", "FILE_DELETION",
      "FILE_MODIFICATION", "FILE_READ", "FILE_COPY", "FILE_OPEN", "FILE_MOVE",
      "FILE_SYNC", "USER_UNCATEGORIZED", "USER_LOGIN", "USER_LOGOUT",
      "USER_CREATION", "USER_CHANGE_PASSWORD", "USER_CHANGE_PERMISSIONS",
      "USER_BADGE_IN", "USER_DELETION", "USER_RESOURCE_CREATION",
      "USER_RESOURCE_UPDATE_CONTENT", "USER_RESOURCE_UPDATE_PERMISSIONS",
      "USER_COMMUNICATION", "USER_RESOURCE_ACCESS", "USER_RESOURCE_DELETION",
      "GROUP_UNCATEGORIZED", "GROUP_CREATION", "GROUP_DELETION",
      "GROUP_MODIFICATION", "EMAIL_UNCATEGORIZED", "EMAIL_TRANSACTION",
      "NETWORK_UNCATEGORIZED", "NETWORK_FLOW", "NETWORK_CONNECTION",
      "NETWORK_FTP", "NETWORK_DHCP", "NETWORK_DNS", "NETWORK_HTTP",
      "NETWORK_SMTP", "STATUS_UNCATEGORIZED", "STATUS_HEARTBEAT",
      "STATUS_STARTUP", "STATUS_SHUTDOWN", "STATUS_UPDATE",
      "SCAN_UNCATEGORIZED", "SCAN_FILE", "SCAN_PROCESS", "SCAN_HOST",
      "SCAN_VULN_HOST", "SCAN_VULN_NETWORK", "SCAN_NETWORK",
      "SCHEDULED_TASK_UNCATEGORIZED", "SCHEDULED_TASK_CREATION",
      "SCHEDULED_TASK_DELETION", "SCHEDULED_TASK_ENABLE",
      "SCHEDULED_TASK_DISABLE", "SCHEDULED_TASK_MODIFICATION",
      "SYSTEM_AUDIT_LOG_UNCATEGORIZED", "SYSTEM_AUDIT_LOG_WIPE",
      "SERVICE_UNSPECIFIED", "SERVICE_CREATION", "SERVICE_DELETION",
      "SERVICE_START", "SERVICE_STOP", "SERVICE_MODIFICATION", "GENERIC_EVENT",
      "RESOURCE_CREATION", "RESOURCE_DELETION", "RESOURCE_PERMISSIONS_CHANGE",
      "RESOURCE_READ", "RESOURCE_WRITTEN")

  network_direction_values = ("UNKNOWN_DIRECTION", "INBOUND", "OUTBOUND",
                              "BROADCAST")

  network_ip_protocol_values = ("UNKNOWN_IP_PROTOCOL", "ICMP", "IGMP", "TCP",
                                "UDP", "IP6IN4", "GRE", "ESP", "EIGRP",
                                "ETHERIP", "PIM", "VRRP")

  network_application_protocol_values = (
      "UNKNOWN_APPLICATION_PROTOCOL", "AFP", "APPC", "AMQP", "ATOM", "BEEP",
      "BITCOIN", "BIT_TORRENT", "CFDP", "COAP", "DDS", "DEVICE_NET", "DHCP",
      "DNS", "E_DONKEY", "ENRP", "FAST_TRACK", "FINGER", "FREENET", "FTAM",
      "GOPHER", "HL7", "H323", "HTTP", "HTTPS", "IRCP", "KADEMLIA", "LDAP",
      "LPD", "MIME", "MODBUS", "MQTT", "NETCONF", "NFS", "NIS", "NNTP", "NTCIP",
      "NTP", "OSCAR", "PNRP", "QUIC", "RDP", "RELP", "RIP", "RLOGIN", "RPC",
      "RTMP", "RTP", "RTPS", "RTSP", "SAP", "SDP", "SIP", "SLP", "SMB", "SMTP",
      "SNTP", "SSH", "SSMS", "STYX", "TCAP", "TDS", "TOR", "TSP", "VTP",
      "WHOIS", "WEB_DAV", "X400", "X500", "XMPP")

  platform_values = ("UNKNOWN_PLATFORM", "WINDOWS", "MAC", "LINUX")

  # Each "p_xxx()" method is a parsing rule, based on the tokens defined in the
  # Lexer class. The docstrings specify a context-free grammar, and the code
  # constructs the parsed rule to enable automated and manual semantic analysis.

  # "p[n]" refers to the n'th elementh in the docstring. For example, given the
  # docstring "aaa : bbb CCCC", p[0] is the value we *assign* to the grammar
  # rule "aaa", using the p[1] value that we *get* for the already-parsed
  # grammar rule "bbb" and the p[2] value of the Lexer token "CCC".

  def p_rule(self, p):
    """rule : comment RULE_NAME '{' sections comment '}'"""
    rule_name = p[2].split()[-1]
    p[0] = dict([("name", rule_name)] + p[4])

  def p_comment(self, _):
    """comment : empty

               | comment MULTI_LINE_COMMENT
               | comment SINGLE_LINE_COMMENT
               | MULTI_LINE_COMMENT
               | SINGLE_LINE_COMMENT
    """

  def p_empty(self, _):
    """empty :"""

  def p_error(self, p):
    raise RuntimeError("Unexpected token in line " +
                       f"{p.lexer.lineno}: '{p.value}'.")

  # YARA-L rule sections.

  def p_sections(self, p):
    """sections : meta_section events_section condition_section

                | meta_section events_section match_section condition_section
    """
    p[0] = [("meta", p[1]), ("events", p[2])]
    # The match section is optional.
    if len(p) < 5:
      p[0] += [("match", None), ("condition", p[3])]
    else:
      p[0] += [("match", p[3]), ("condition", p[4])]

  def p_meta_section(self, p):
    """meta_section : META_LABEL meta_lines"""
    p[0] = p[2]

  def p_events_section(self, p):
    """events_section : comment EVENTS_LABEL events_lines"""
    p[0] = p[3]

  def p_match_section(self, p):
    """match_section : comment MATCH_LABEL comment match_line"""
    p[0] = p[4]

  def p_condition_section(self, p):
    """condition_section : comment CONDITION_LABEL comment condition_line"""
    p[0] = p[4]

  # Separate lines in sections that support multiple lines.

  def p_meta_lines(self, p):
    """meta_lines : meta_lines comment META_LINE

                  | comment META_LINE
    """
    # We have to use p[len(p)-1] because the Pythonic p[-1] means something else
    # in PLY (https://ply.readthedocs.io/en/latest/ply.html#embedded-actions).
    meta_line = p[len(p) - 1].split(maxsplit=2)  # meta_line = [key, "=", value]
    key, value = meta_line[0], meta_line[2][1:-1]  # Strip quotes from value.
    if len(p) == 3:
      p[0] = [(key, value)]  # First meta line.
    else:
      p[0] = p[1] + [(key, value)]  # Append to previous meta lines.

  def p_events_lines(self, p):
    """events_lines : events_lines comment events_line

                    | comment events_line
    """
    if len(p) == 3:
      p[0] = [p[2]]  # First event line.
    else:
      p[0] = p[1] + [p[3]]  # Append to previous event lines.

  # Specific events.

  def p_events_line(self, p):
    """events_line : '(' events_line ')'

                   | NOT events_line
                   | events_line AND events_line
                   | events_line OR events_line

                   | variable EQ variable
                   | variable EQ STRING
                   | variable EQ STRING NOCASE
                   | variable EQ RAW_STRING
                   | variable EQ RAW_STRING NOCASE
                   | variable EQ REGEX
                   | variable EQ REGEX NOCASE
                   | variable EQ NUMBER

                   | variable NE variable
                   | variable NE STRING
                   | variable NE STRING NOCASE
                   | variable NE RAW_STRING
                   | variable NE RAW_STRING NOCASE
                   | variable NE NUMBER

                   | variable GT variable
                   | variable GE variable
                   | variable LT variable
                   | variable LE variable

                   | variable GT NUMBER
                   | variable GE NUMBER
                   | variable LT NUMBER
                   | variable LE NUMBER

                   | NET_IP_IN_RANGE_CIDR '(' variable ',' STRING ')'

                   | RE_REGEX '(' variable ',' STRING ')'
                   | RE_REGEX '(' variable ',' RAW_STRING ')'
                   | RE_REGEX '(' variable ',' STRING ')' NOCASE
                   | RE_REGEX '(' variable ',' RAW_STRING ')' NOCASE
    """
    # NOT events_line.
    if p[1] == "not":
      p[0] = (p[1], p[2])
    # '(' events_line ')'.
    elif p[1] == "(" and p[3] == ")":
      p[0] = p[2]
    # "events_line <AND|OR> events_line".
    elif p[2] in ("and", "or"):
      event1, operator, event2 = p[1], p[2], p[3]
      p[0] = (operator, event1, event2)
    # "variable <OP> <...>".
    # Note: "CONST <OP> variable" is valid in Chronicle's rules engine,
    # but it's considered as bad style so we don't recognize it here.
    elif p[1].startswith("$"):
      variable, operator, value = p[1], p[2], p[3]
      if p[len(p) - 1] == "nocase":
        value += " nocase"
      p[0] = (operator, variable, value)
      # Sanity check for the validity of enum values.
      if operator in ("=", "!="):
        self.check_enum_values(variable, p[3][1:-1])
    # Functions with 2 parameters.
    else:
      func, arg1, arg2 = p[1], p[3], p[5]
      if p[len(p) - 1] == "nocase":
        arg2 += " nocase"
      p[0] = (func, arg1, arg2)

  # Specific matches.

  def p_match_line(self, p):
    """match_line : match_variables TIME_WINDOW"""
    p[0] = {"variables": p[1], "time_window": p[2].split()[-1]}

  def p_match_variables(self, p):
    """match_variables : match_variables ',' variable

                       | variable
    """
    if len(p) == 2:
      p[0] = [p[1]]  # First variable.
    else:
      p[0] = p[1] + [p[3]]  # Append to previous variables.

  # Condition line.

  def p_condition_line(self, p):
    """condition_line : '(' condition_line ')'

                      | condition_line AND condition_line
                      | condition_line OR condition_line

                      | variable
                      | '!' variable

                      | COUNTER EQ NUMBER
                      | COUNTER NE NUMBER
                      | COUNTER GT NUMBER
                      | COUNTER GE NUMBER
                      | COUNTER LT NUMBER
                      | COUNTER LE NUMBER
    """
    # variable.
    if len(p) == 2:
      p[0] = p[1]
    # '!' variable.
    elif len(p) == 3 and p[1] == "!":
      p[0] = ("!", p[2])
    # '(' condition_line ')'.
    elif p[1] == "(" and p[3] == ")":
      p[0] = p[2]
    # condition_line <AND|OR> condition_line.
    # COUNTER <EQ|NE|GT|GE|LT|LE> NUMBER.
    else:
      p[0] = (p[2], p[1], p[3])

  # Event variables - this is where we we check the validity of UDM field names
  # and enum fields.

  def p_variable(self, p):
    """variable : VARIABLE_NAME

                | VARIABLE_NAME variable_fields
    """
    p[0] = "".join(p[1:])
    if len(p) == 3:
      top_level_field = p[2].split(".")[1]
      if top_level_field not in Parser.udm_top_level_fields:
        raise RuntimeError(
            f"Invalid UDM field '{top_level_field}' in variable '{p[0]}'")

  def p_variable_fields(self, p):
    """variable_fields : VARIABLE_FIELD

                       |  VARIABLE_FIELD variable_fields
    """
    p[0] = "".join(p[1:])
    if len(p) == 3:
      parent, child = p[1][1:], p[2].split(".")[1]
      if self.check_udm_field(parent, child, Parser.udm_nouns,
                              Parser.udm_noun_fields):
        return
      if self.check_udm_field(parent, child, "dns", Parser.udm_dns_fields):
        return
      if self.check_udm_field(parent, child, "file", Parser.udm_file_fields):
        return
      if self.check_udm_field(parent, child, "http", Parser.udm_http_fields):
        return
      if self.check_udm_field(parent, child, "metadata",
                              Parser.udm_metadata_fields):
        return
      if self.check_udm_field(parent, child, "network",
                              Parser.udm_network_fields):
        return
      if self.check_udm_field(parent, child, "process",
                              Parser.udm_process_fields):
        return
      if self.check_udm_field(parent, child, "questions",
                              Parser.udm_dns_questions_fields):
        return
      if self.check_udm_field(parent, child, "registry",
                              Parser.udm_registry_fields):
        return
      else:
        raise RuntimeError(f"Unexpected UDM field '{child}' under '{parent}'")

  def check_enum_values(self, variable, value):
    if self.check_enum_value(variable, value, "metadata.event_type",
                             Parser.metadata_event_type_values):
      return
    if self.check_enum_value(variable, value, "network.direction",
                             Parser.network_direction_values):
      return
    if self.check_enum_value(variable, value, "network.ip_protocol",
                             Parser.network_ip_protocol_values):
      return
    if self.check_enum_value(variable, value, "network.application_protocol",
                             Parser.network_application_protocol_values):
      return
    if self.check_enum_value(variable, value, "platform",
                             Parser.platform_values):
      return

  def check_enum_value(self, variable, value, suffix, valid_values):
    if variable.endswith(f".{suffix}"):
      if value not in valid_values:
        raise RuntimeError(f"Unrecognized enum value: {variable[1:]} = {value}")
      else:
        return True
    else:
      return False

  def check_udm_field(self, parent, child, parents, valid_children):
    if isinstance(parents, tuple):
      if parent in parents:
        if child not in valid_children:
          raise RuntimeError(f"Unexpected UDM field '{child}' under '{parent}'")
        else:
          return True
      else:
        return False
    else:
      if parent == parents:
        if child not in valid_children:
          raise RuntimeError(f"Unexpected UDM field '{child}' under '{parent}'")
        else:
          return True
      else:
        return False


class SyntaxTest(unittest.TestCase):
  """Syntactic unit-test for all discoverable YALA-L files."""

  def test_yaral(self):
    cwd = pathlib.Path.cwd()
    print(f"Current directory: {cwd}")
    for i, absolute_path in enumerate(sorted(cwd.rglob("*.yaral")), start=1):
      relative_path = str(absolute_path.relative_to(cwd))
      with self.subTest(i=i, path=relative_path):
        rule = absolute_path.read_text(encoding="utf-8").strip()
        print(f"\nFile {i}: {relative_path}\n")

        # Test the correct tokenization of each file.
        lexer = lex.lex(module=Lexer())
        lexer.input(rule)
        while True:
          token = lexer.token()
          if not token:
            break
          print(token)
        print("")

        # Test the correct parsing of each file.
        parser = yacc.yacc(
            module=Parser(),
            debugfile=f"parser_{i}.out")
        result = parser.parse(rule, lexer=lex.lex(module=Lexer()))
        pprint.pprint(result, indent=2, sort_dicts=False)


if __name__ == "__main__":
  unittest.main()
