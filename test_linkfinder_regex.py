#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Prueba del regex del LinkFinder sin depender de Burp."""
import re

REGEX_STR = r"""
  (?:"|'|`)                             # Start delimiter: quote or backtick

  (
    ((?:[a-zA-Z]{1,10}://|//)           # Scheme: http(s), ws(s), //, etc.
    [^"'`/]{1,}\.                       # Domain (must contain a dot)
    [a-zA-Z]{2,}[^"'`]{0,})            # TLD and path

    |

    ((?:/|\.\./|\./)                    # Paths: /, ../, ./
    [^"'`><,;| *()(%%$^/\\\[\]]         # First char restrictions
    [^"'`><,;|()]{1,})                  # Rest of path

    |

    ([a-zA-Z0-9_\-/]{1,}/               # Relative: segment/
    [a-zA-Z0-9_.\-/]{1,}                # resource name (allow dotted filenames)
    \.(?:[a-zA-Z]{1,6}|action)          # .ext (1-6 chars) or .action
    (?:[\?|/][^"'`|]{0,}|))            # Optional ? or / and params

    |

    ([a-zA-Z0-9_.\-]{1,}                # Filename.extension (allow dotted filenames)
    \.(?:php|asp|aspx|ashx|asmx|svc|jsp|json|do|cgi|pl|cfm|
         action|html|htm|js|mjs|cjs|jsx|ts|tsx|vue|txt|xml|yaml|yml|config|map) # Common backend/API extensions
    (?:\?[^"'`|]{0,}|))                # Optional query

    |

    ([a-zA-Z0-9_\-]{1,}                 # Handler without extension
    \?[^"'`|]{0,})                      # ?query

  )

  (?:"|'|`)                             # End delimiter
"""


def parser_file(content, regex_str, no_dup=True):
    regex = re.compile(regex_str, re.VERBOSE)
    items = []
    for m in re.finditer(regex, content):
        link = next((g for g in m.groups() if g is not None), None)
        if link:
            items.append({"link": link})
    if no_dup:
        seen = set()
        unique = []
        for item in items:
            if item["link"] not in seen:
                seen.add(item["link"])
                unique.append(item)
        items = unique
    return items


# Contenido JS de prueba (como en la imagen y variantes)
SAMPLE_JS = """
var profileImagePath = dnn.getVar("sf_siteRoot", "/") +
  'DnnImageHandler.ashx?mode=securefile&fileId=' + fileId + '&MaxWidth=' + maxwidth + '&MaxHeight=' + maxHeight;

var other = "DnnImageHandler?mode=securefile&fileId=";
var url = 'https://api.ejemplo.com/v1/users';
var path = "/api/config.json";
var rel = "../utils.js";

var ws = `wss://realtime.ejemplo.com/socket`;
var svc = "https://api.com/Service.svc/GetData";
var config = "/app/settings.config";
var sourceMap = "assets/app.bundle.js.map";
var component = "../components/LoginForm.vue";
var tsModule = "./api/client.ts";
var jsxView = "views/Dashboard.jsx";
var esmModule = "./runtime/bootstrap.mjs";
var cjsModule = "../server/index.cjs";
var yamlConfig = "/config/openapi.yaml";
var ymlConfig = "./pipelines/build.yml";
"""


def main():
    print("=== Prueba regex LinkFinder ===\n")
    print("Contenido de prueba (fragmento JS):")
    print(SAMPLE_JS)
    print("\n--- Enlaces detectados ---")
    items = parser_file(SAMPLE_JS, REGEX_STR)
    for i, item in enumerate(items, 1):
        print("  %d - %s" % (i, item["link"]))
    print("\nTotal: %d enlaces" % len(items))


if __name__ == "__main__":
    main()
