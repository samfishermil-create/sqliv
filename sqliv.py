# SQLiv v2.0
# Ghost (github.com/Hadesy2k)
# official.ghost@tuta.io

import argparse
import os
import sys
from urlparse import urlparse
import math

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

# engine map for safe lookup
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
    if urlparse(url).query != '':
        result = scanner.scan([url])
        if result:
            # scanner.scan prints if vulnerable; return the results
            return result
        else:
            # give user option to crawl and continue scanning
            try:
                print ""  # move carriage return to newline (Python 2)
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
    """Initialize parser arguments and return the parser."""
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
    websites = []

    # find random SQLi by dork (search engines)
    if args.dork is not None and args.engine is not None:
        std.stdout("searching for websites with given dork(s)")

        engine_name = args.engine.lower()
        if engine_name not in ENGINES:
            std.stderr("invalid search engine")
            return 1

        engine = ENGINES[engine_name]

        # read dorks (single or file)
        dorks = _read_dorks(args.dork)

        all_websites = []
        # For each dork, run paginated search and show per-page info if available
        for dork in dorks:
            std.stdout("dork: {}".format(dork))
            try:
                # Prefer search_verbose if available (returns (urls, pages_info))
                if hasattr(engine, 'search_verbose'):
                    urls, pages_info = engine.search_verbose(dork, args.page)
                    # print per-page info if provided
                    if pages_info:
                        for page in pages_info:
                            # page is expected to be dict with keys: page, request, results, status or status_ok
                            if page.get('status_ok'):
                                std.stdout("[{}] {} -> results: {}".format(page.get('page'), page.get('request'), page.get('results')))
                            else:
                                std.stderr("[{}] {} -> error: {}".format(page.get('page'), page.get('request'), page.get('status')))
                else:
                    # fallback to simple search
                    urls = engine.search(dork, args.page)

            except Exception as e:
                std.stderr("search error for dork '{}': {}".format(dork, e))
                continue

            # extend master list, avoid duplicates
            for u in urls:
                if u not in all_websites:
                    all_websites.append(u)

        std.stdout("{} websites found (aggregated)".format(len(all_websites)))

        if not all_websites:
            if args.s:
                std.stdout("saved as searches.txt")
                std.dump(all_websites, "searches.txt")
            return 0

        # scan found websites
        vulnerables = scanner.scan(all_websites)

        if not vulnerables:
            if args.s:
                std.stdout("saved as searches.txt")
                std.dump(all_websites, "searches.txt")
            return 0

        std.stdout("scanning server information")

        vulnerableurls = [result[0] for result in vulnerables]
        table_data = serverinfo.check(vulnerableurls)

        # print results
        std.normalprint(vulnerables)
        std.printserverinfo(table_data)

        # Save vulnerable urls to file if requested
        if args.output:
            vuln_urls = [v[0] for v in vulnerables]
            if args.json:
                std.dumpjson(vuln_urls, args.output)
            else:
                std.dump(vuln_urls, args.output)
            std.stdout("vulnerable urls saved to {}".format(args.output))

        # Ask about crawling and further scanning (optional)
        option = std.stdin("do you want to crawl and continue scanning? [Y/N]", ["Y", "N"], upper=True)
        if option == 'N':
            return 0

        # If user wants to continue crawling, fall through to crawl/target logic below (using first vulnerable url as seed)
        seed_url = vulnerableurls[0]
        std.stdout("going to crawl {}".format(seed_url))
        urls = crawler.crawl(seed_url)
        if urls:
            extra_vuln = scanner.scan(urls)
            if extra_vuln:
                vulnerables += extra_vuln
                std.normalprint(vulnerables)

        return 0

    # do reverse domain of given site
    if args.target is not None and args.reverse:
        std.stdout("finding domains with same server as {}".format(args.target))
        domains = reverseip.reverseip(args.target)

        if not domains:
            std.stdout("no domain found with reversing ip")
            return 0

        std.stdout("found {} websites".format(len(domains)))

        # ask whether user wants to save domains
        std.stdout("scanning multiple websites with crawling will take long")
        option = std.stdin("do you want save domains? [Y/N]", ["Y", "N"], upper=True)

        if option == 'Y':
            std.stdout("saved as domains.txt")
            std.dump(domains, "domains.txt")

        # ask whether user wants to crawl one by one or exit
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
        # optionally dump
        if args.output:
            if args.json:
                std.dumpjson(table_data, args.output)
            else:
                std.dump(vulnerableurls, args.output)
        return 0

    # scan SQLi of given site (single target without reverse)
    if args.target and not args.reverse:
        vulnerables = singlescan(args.target)

        if not vulnerables:
            return 0

        # show domain information of target urls
        std.stdout("getting server info of domains can take a few mins")
        table_data = serverinfo.check([args.target])

        std.printserverinfo(table_data)
        try:
            print ""  # give space between two table
        except Exception:
            pass
        std.normalprint(vulnerables)
        return 0

    # If no parameters provided, print help
    parser.print_help()
    return 0


if __name__ == "__main__":
    # Execute main and exit with its return code
    raise SystemExit(main())        else:
            print ""  # move carriage return to newline
            std.stdout("no SQL injection vulnerability found")
            option = std.stdin("do you want to crawl and continue scanning? [Y/N]", ["Y", "N"], upper=True)

            if option == 'N':
                return False

    # crawl and scan the links
    std.stdout("going to crawl {}".format(url))
    urls = crawler.crawl(url)

    if not urls:
        std.stdout("found no suitable urls to test SQLi")
        # std.stdout("you might want to do reverse domain")
        return False

    std.stdout("found {} urls from crawling".format(len(urls)))
    vulnerables = scanner.scan(urls)

    if vulnerables == []:
        std.stdout("no SQL injection vulnerability found")
        return False

    return vulnerables


def initparser():
    """initialize parser arguments"""

    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", dest="dork", help="SQL injection dork or dork file (one dork per line)", type=str, metavar="inurl:example or dorks.txt")
    parser.add_argument("-e", dest="engine", help="search engine [Bing, Google, and Yahoo]", type=str, metavar="bing, google, yahoo")
    parser.add_argument("-p", dest="page", help="number of websites to look for in search engine", type=int, default=10, metavar="100")
    parser.add_argument("-t", dest="target", help="scan target website", type=str, metavar="www.example.com")
    parser.add_argument('-r', dest="reverse", help="reverse domain", action='store_true')
    parser.add_argument('-o', dest="output", help="output vulnerable URLs into file (one URL per line) or json when used with --json", type=str, metavar="result.txt")
    parser.add_argument('-s', action='store_true', help="output search even if there are no results")
    parser.add_argument('--json', action='store_true', help="output final results as json (used with -o)")


def _read_dorks(dork_arg):
    """Read dorks from a file or treat the argument as a single dork string."""
    # If dork_arg is a file path, read lines; else return [dork_arg]
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


def main():
    initparser()
    args = parser.parse_args()

    table_data = None
    vulnerables = None

    # find random SQLi by dork
    if args.dork is not None and args.engine is not None:
        std.stdout("searching for websites        else:
            print ""  # move carriage return to newline
            std.stdout("no SQL injection vulnerability found")
            option = std.stdin("do you want to crawl and continue scanning? [Y/N]", ["Y", "N"], upper=True)

            if option == 'N':
                return False

    # crawl and scan the links
    # if crawl cannot find links, do some reverse domain
    std.stdout("going to crawl {}".format(url))
    urls = crawler.crawl(url)

    if not urls:
        std.stdout("found no suitable urls to test SQLi")
        #std.stdout("you might want to do reverse domain")
        return False

    std.stdout("found {} urls from crawling".format(len(urls)))
    vulnerables = scanner.scan(urls)

    if vulnerables == []:
        std.stdout("no SQL injection vulnerability found")
        return False

    return vulnerables


def initparser():
    """initialize parser arguments"""

    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", dest="dork", help="SQL injection dork or dork file (one dork per line)", type=str, metavar="inurl:example or dorks.txt")
    parser.add_argument("-e", dest="engine", help="search engine [Bing, Google, and Yahoo]", type=str, metavar="bing, google, yahoo")
    parser.add_argument("-p", dest="page", help="number of websites to look for in search engine", type=int, default=10, metavar="100")
    parser.add_argument("-t", dest="target", help="scan target website", type=str, metavar="www.example.com")
    parser.add_argument('-r', dest="reverse", help="reverse domain", action='store_true')
    parser.add_argument('-o', dest="output", help="output vulnerable URLs into file (one URL per line)", type=str, metavar="result.txt")
    parser.add_argument('-s', action='store_true', help="output search even if there are no results")


def _read_dorks(dork_arg):
    """Read dorks from a file or treat the argument as a single dork string."""
    # If dork_arg is a file path, read lines; else return [dork_arg]
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


if __name__ == "__main__":
    initparser()
    args = parser.parse_args()

    # find random SQLi by dork
    if args.dork != None and args.engine != None:
        std.stdout("searching for websites with given dork(s)")

        # validate engine
        if args.engine not in ["bing", "google", "yahoo"]:
            std.stderr("invalid search engine")
            exit(1)

        # read dorks (single or file)
        dorks = _read_dorks(args.dork)

        all_websites = []
        # For each dork, run paginated search and show per-page info
        for dork in dorks:
            std.stdout("dork: {}".format(dork))
            try:
                # search_verbose returns (urls, pages_info)
                urls, pages_info = eval(args.engine).search_verbose(dork, args.page)
            except Exception as e:
                std.stderr("search error for dork '{}': {}".format(dork, e))
                continue

            # print per-page info
            for page in pages_info:
                # page is dict with keys: page, request, results, status
                if page.get('status_ok'):
                    std.stdout("[{}] {} -> results: {}".format(page.get('page'), page.get('request'), page.get('results')))
                else:
                    std.stderr("[{}] {} -> error: {}".format(page.get('page'), page.get('request'), page.get('status')))

            std.stdout("total websites found for this dork: {}".format(len(urls)))
            # extend master list, avoid duplicates
            for u in urls:
                if u not in all_websites:
                    all_websites.append(u)

        std.stdout("{} websites found (aggregated)".format(len(all_websites)))

        if not all_websites:
            if args.s:
                std.stdout("saved as searches.txt")
                std.dump(all_websites, "searches.txt")
            exit(0)

        vulnerables = scanner.scan(all_websites)

        if not vulnerables:
            if args.s:
                std.stdout("saved as searches.txt")
                std.dump(all_websites, "searches.txt")
            exit(0)

        std.stdout("scanning server information")

        vulnerableurls = [result[0] for result in vulnerables]
        table_data = serverinfo.check(vulnerableurls)

        # print results as before
        std.std = std  # keep reference to avoid linter warnings
        std.normalprint(vulnerables)
        std.printserverinfo(table_data)

        # Save vulnerable urls to file if requested (one url per line)
        if args.output:
            vuln_urls = [v[0] for v in vulnerables]
            std.dump(vuln_urls, args.output)
            std.stdout("vulnerable urls saved to {}".format(args.output))
            std.stdout("no SQL injection vulnerability found")
            option = std.stdin("do you want to crawl and continue scanning? [Y/N]", ["Y", "N"], upper=True)

            if option == 'N':
                return False

    # crawl and scan the links
    # if crawl cannot find links, do some reverse domain
    std.stdout("going to crawl {}".format(url))
    urls = crawler.crawl(url)

    if not urls:
        std.stdout("found no suitable urls to test SQLi")
        #std.stdout("you might want to do reverse domain")
        return False

    std.stdout("found {} urls from crawling".format(len(urls)))
    vulnerables = scanner.scan(urls)

    if vulnerables == []:
        std.stdout("no SQL injection vulnerability found")
        return False

    return vulnerables


def initparser():
    """initialize parser arguments"""

    global parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", dest="dork", help="SQL injection dork", type=str, metavar="inurl:example")
    parser.add_argument("-e", dest="engine", help="search engine [Bing, Google, and Yahoo]", type=str, metavar="bing, google, yahoo")
    parser.add_argument("-p", dest="page", help="number of websites to look for in search engine", type=int, default=10, metavar="100")
    parser.add_argument("-t", dest="target", help="scan target website", type=str, metavar="www.example.com")
    parser.add_argument('-r', dest="reverse", help="reverse domain", action='store_true')
    parser.add_argument('-o', dest="output", help="output result into json", type=str, metavar="result.json")
    parser.add_argument('-s', action='store_true', help="output search even if there are no results")


if __name__ == "__main__":
    initparser()
    args = parser.parse_args()

    # find random SQLi by dork
    if args.dork != None and args.engine != None:
        std.stdout("searching for websites with given dork")

        # get websites based on search engine
        if args.engine in ["bing", "google", "yahoo"]:
            websites = eval(args.engine).search(args.dork, args.page)
        else:
            std.stderr("invalid search engine")
            exit(1)

        std.stdout("{} websites found".format(len(websites)))

        vulnerables = scanner.scan(websites)

        if not vulnerables:
            if args.s:
                std.stdout("saved as searches.txt")
                std.dump(websites, "searches.txt")

            exit(0)

        std.stdout("scanning server information")

        vulnerableurls = [result[0] for result in vulnerables]
        table_data = serverinfo.check(vulnerableurls)
        # add db name to info
        for result, info in zip(vulnerables, table_data):
            info.insert(1, result[1])  # database name

        std.fullprint(table_data)


    # do reverse domain of given site
    elif args.target != None and args.reverse:
        std.stdout("finding domains with same server as {}".format(args.target))
        domains = reverseip.reverseip(args.target)

        if domains == []:
            std.stdout("no domain found with reversing ip")
            exit(0)

        # if there are domains
        std.stdout("found {} websites".format(len(domains)))

        # ask whether user wants to save domains
        std.stdout("scanning multiple websites with crawling will take long")
        option = std.stdin("do you want save domains? [Y/N]", ["Y", "N"], upper=True)

        if option == 'Y':
            std.stdout("saved as domains.txt")
            std.dump(domains, "domains.txt")

        # ask whether user wants to crawl one by one or exit
        option = std.stdin("do you want start crawling? [Y/N]", ["Y", "N"], upper=True)

        if option == 'N':
            exit(0)

        vulnerables = []
        for domain in domains:
            vulnerables_temp = singlescan(domain)
            if vulnerables_temp:
                vulnerables += vulnerables_temp

        std.stdout("finished scanning all reverse domains")
        if vulnerables == []:
            std.stdout("no vulnerables webistes from reverse domains")
            exit(0)

        std.stdout("scanning server information")

        vulnerableurls = [result[0] for result in vulnerables]
        table_data = serverinfo.check(vulnerableurls)
        # add db name to info
        for result, info in zip(vulnerables, table_data):
            info.insert(1, result[1])  # database name

        std.fullprint(table_data)


    # scan SQLi of given site
    elif args.target:
        vulnerables = singlescan(args.target)

        if not vulnerables:
            exit(0)

        # show domain information of target urls
        std.stdout("getting server info of domains can take a few mins")
        table_data = serverinfo.check([args.target])

        std.printserverinfo(table_data)
        print ""  # give space between two table
        std.normalprint(vulnerables)
        exit(0)

    # print help message, if no parameter is provided
    else:
        parser.print_help()

    # dump result into json if specified
    if args.output != None:
        std.dumpjson(table_data, args.output)
        std.stdout("Dumped result into %s" % args.output)

