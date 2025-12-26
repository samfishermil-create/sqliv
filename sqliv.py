# SQLiv v2.0 - syntax fixed and unified
# Ghost (github.com/Hadesy2k)
# official.ghost@tuta.io

from __future__ import print_function

import argparse
import os
import sys
import math

# urlparse compatibility for Python2 / Python3
try:
    from urllib.parse import urlparse
except Exception:
    from urlparse import urlparse

from src import std
from src import scanner
from src import reverseip
from src import serverinfo
from src.web import search
from src.crawler import Crawler


# search engine instances
bing = search.Bing()
google = search.Google()
yahoo = search.Yahoo()

ENGINES = {
    "bing": bing,
    "google": google,
    "yahoo": yahoo,
}

# crawler instance
crawler = Crawler()


def singlescan(url):
    """Instance to scan a single targeted domain.

    Returns:
      - list of vulnerable results if found
      - False if none or on abort
    """
    # If the URL contains a query string, test it directly first
    try:
        has_query = urlparse(url).query != ''
    except Exception:
        has_query = False

    if has_query:
        result = scanner.scan([url])
        if result:
            # scanner.scan prints when vulnerable; return the results
            return result
        else:
            # write newline (works for py2/py3)
            try:
                sys.stdout.write("\n")
            except Exception:
                pass
            std.stdout("no SQL injection vulnerability found")
            option = std.stdin("do you want to crawl and continue scanning? [Y/N]", ["Y", "N"], upper=True)
            if option == 'N':
                return False

    # Crawl and scan the links
    std.stdout("going to crawl {}".format(url))
    urls = crawler.crawl(url)

    if not urls:
        std.stdout("found no suitable urls to test SQLi")
        return False

    std.stdout("found {} urls from crawling".format(len(urls)))
    vulnerables = scanner.scan(urls)

    if not vulnerables:
        std.stdout("no SQL injection vulnerability found")
        return False

    return vulnerables


def _read_dorks(dork_arg):
    """Read dorks from a file or treat the argument as a single dork string."""
    if not dork_arg:
        return []

    if os.path.isfile(dork_arg):
        dorks = []
        with open(dork_arg, 'r') as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                # ignore comments starting with #
                if line.startswith("#"):
                    continue
                dorks.append(line)
        return dorks
    else:
        return [dork_arg]


def initparser():
    """Initialize and return the argument parser."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", dest="dork", help="SQL injection dork or dork file (one dork per line)", type=str, metavar="inurl:example or dorks.txt")
    parser.add_argument("-e", dest="engine", help="search engine [bing, google, yahoo]", type=str, metavar="bing, google, yahoo")
    parser.add_argument("-p", dest="page", help="number of websites to look for in search engine", type=int, default=10, metavar="100")
    parser.add_argument("-t", dest="target", help="scan target website", type=str, metavar="www.example.com")
    parser.add_argument('-r', dest="reverse", help="reverse domain", action='store_true')
    parser.add_argument('-o', dest="output", help="output vulnerable URLs into file (one URL per line) or json when used with --json", type=str, metavar="result.txt")
    parser.add_argument('-s', action='store_true', help="output search even if there are no results")
    parser.add_argument('--json', action='store_true', help="output final results as json (used with -o)")
    return parser


def main():
    parser = initparser()
    args = parser.parse_args()

    table_data = None
    vulnerables = None

    # Mode: search by dork(s) using search engine
    if args.dork is not None and args.engine is not None:
        std.stdout("searching for websites with given dork(s)")

        engine_name = args.engine.lower()
        if engine_name not in ENGINES:
            std.stderr("invalid search engine")
            return 1

        engine = ENGINES[engine_name]

        # read dorks (single string or file)
        dorks = _read_dorks(args.dork)
        all_websites = []

        for dork in dorks:
            std.stdout("dork: {}".format(dork))
            try:
                # Prefer verbose search if available
                if hasattr(engine, "search_verbose"):
                    urls, pages_info = engine.search_verbose(dork, args.page)
                    if pages_info:
                        for page in pages_info:
                            if page.get('status_ok'):
                                std.stdout("[{}] {} -> results: {}".format(page.get('page'), page.get('request'), page.get('results')))
                            else:
                                std.stderr("[{}] {} -> error: {}".format(page.get('page'), page.get('request'), page.get('status')))
                else:
                    urls = engine.search(dork, args.page)
            except Exception as e:
                std.stderr("search error for dork '{}': {}".format(dork, e))
                continue

            for u in urls:
                if u not in all_websites:
                    all_websites.append(u)

        std.stdout("{} websites found (aggregated)".format(len(all_websites)))

        if not all_websites:
            if args.s:
                std.stdout("saved as searches.txt")
                std.dump(all_websites, "searches.txt")
            return 0

        vulnerables = scanner.scan(all_websites)

        if not vulnerables:
            if args.s:
                std.stdout("saved as searches.txt")
                std.dump(all_websites, "searches.txt")
            return 0

        std.stdout("scanning server information")
        vulnerableurls = [result[0] for result in vulnerables]
        table_data = serverinfo.check(vulnerableurls)

        std.normalprint(vulnerables)
        std.printserverinfo(table_data)

        if args.output:
            vuln_urls = [v[0] for v in vulnerables]
            if args.json:
                std.dumpjson(vuln_urls, args.output)
            else:
                std.dump(vuln_urls, args.output)
            std.stdout("vulnerable urls saved to {}".format(args.output))

        # Optionally allow crawling/scanning more
        option = std.stdin("do you want to crawl and continue scanning? [Y/N]", ["Y", "N"], upper=True)
        if option == 'N':
            return 0

        # If continue, seed crawl from first vulnerable url
        seed_url = vulnerableurls[0]
        std.stdout("going to crawl {}".format(seed_url))
        urls = crawler.crawl(seed_url)
        if urls:
            extra_vuln = scanner.scan(urls)
            if extra_vuln:
                vulnerables += extra_vuln
                std.normalprint(vulnerables)

        return 0

    # Mode: reverse domains from target
    if args.target is not None and args.reverse:
        std.stdout("finding domains with same server as {}".format(args.target))
        domains = reverseip.reverseip(args.target)

        if not domains:
            std.stdout("no domain found with reversing ip")
            return 0

        std.stdout("found {} websites".format(len(domains)))

        std.stdout("scanning multiple websites with crawling will take long")
        option = std.stdin("do you want save domains? [Y/N]", ["Y", "N"], upper=True)

        if option == 'Y':
            std.stdout("saved as domains.txt")
            std.dump(domains, "domains.txt")

        option = std.stdin("do you want start crawling? [Y/N]", ["Y", "N"], upper=True)
        if option == 'N':
            return 0

        vulnerables = []
        for domain in domains:
            vulnerables_temp = singlescan(domain)
            if vulnerables_temp:
                vulnerables += vulnerables_temp

        std.stdout("finished scanning all reverse domains")
        if not vulnerables:
            std.stdout("no vulnerables webistes from reverse domains")
            return 0

        std.stdout("scanning server information")
        vulnerableurls = [result[0] for result in vulnerables]
        table_data = serverinfo.check(vulnerableurls)

        # add db name to info
        for result, info in zip(vulnerables, table_data):
            info.insert(1, result[1])  # insert database name

        std.fullprint(table_data)

        if args.output:
            if args.json:
                std.dumpjson(table_data, args.output)
            else:
                std.dump(vulnerableurls, args.output)

        return 0

    # Mode: single target scan
    if args.target and not args.reverse:
        vulnerables = singlescan(args.target)

        if not vulnerables:
            return 0

        std.stdout("getting server info of domains can take a few mins")
        table_data = serverinfo.check([args.target])

        std.printserverinfo(table_data)
        try:
            sys.stdout.write("\n")
        except Exception:
            pass
        std.normalprint(vulnerables)
        return 0

    # No parameters: print help
    parser.print_help()
    return 0


if __name__ == "__main__":
    # Execute main and exit with its return code
    raise SystemExit(main())
