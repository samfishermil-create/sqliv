# search vulnerabilities by dork (with verbose per-page search info)

import sys
import math
from urllib import quote_plus
from urllib2 import HTTPError, URLError, Request, urlopen

from lib import bing
from lib import google
from lib import yahoo

bingsearch = bing.Bing()
yahoosearch = yahoo.Yahoo()

class Search:
    """basic search class that can be inherited by other search agents like Google, Yandex"""
    pass

class Google(Search):
    def search(self, query, pages=10):
        """search and return an array of urls"""
        urls = []
        try:
            for url in google.search(query, start=0, stop=pages):
                urls.append(url)
        except HTTPError:
            exit("[503] Service Unreachable")
        except URLError:
            exit("[504] Gateway Timeout")
        except:
            exit("Unknown error occurred")
        else:
            return urls

    def search_verbose(self, query, pages=10):
        """search and return (urls, pages_info)
        pages_info is a list of dicts {page, request, results, status, status_ok}
        pages param is number of websites to look for (default 10). We'll page by 10 results per page.
        """
        urls = []
        pages_info = []
        per_page = 10
        num_pages = max(1, int(math.ceil(float(pages) / per_page)))

        for i in range(num_pages):
            start = i * per_page
            # Construct a friendly request URL (note: not guaranteed identical to google module internals)
            request_url = "https://www.google.com/search?hl=en&q={}&start={}&num={}".format(quote_plus(query), start, per_page)
            try:
                # Use google.search generator to fetch this slice
                page_urls = []
                for url in google.search(query, start=start, stop=start + per_page):
                    page_urls.append(url)
                    if url not in urls:
                        urls.append(url)

                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': len(page_urls),
                    'status': "OK",
                    'status_ok': True
                })
            except HTTPError as he:
                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': 0,
                    'status': "[503] Service Unreachable: {}".format(he),
                    'status_ok': False
                })
            except URLError as ue:
                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': 0,
                    'status': "[504] Gateway Timeout: {}".format(ue),
                    'status_ok': False
                })
            except Exception as e:
                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': 0,
                    'status': "Unknown error occurred: {}".format(e),
                    'status_ok': False
                })

        return urls, pages_info

class Bing(Search):
    def search(self, query, pages=10):
        try:
            return bingsearch.search(query, stop=pages)
        except HTTPError:
            exit("[503] Service Unreachable")
        except URLError:
            exit("[504] Gateway Timeout")
        except:
            exit("Unknown error occurred")

    def search_verbose(self, query, pages=10):
        """Perform per-page Bing searches and return (urls, pages_info)."""
        urls = []
        pages_info = []
        per_page = 10
        num_pages = max(1, int(math.ceil(float(pages) / per_page)))
        for i in range(num_pages):
            start = 1 + i * per_page
            # build same URL as lib/bing.Bing.search
            q = query
            # urlencode q param similarly to bing lib
            try:
                from urllib import urlencode
                qstr = urlencode({'q': q})
            except:
                qstr = "q={}".format(quote_plus(q))

            request_url = "http://www.bing.com/search?{}&first={}".format(qstr, start)
            try:
                # retrieve page html via bing.Bing.get_page for consistent headers
                html = bingsearch.get_page(request_url)
                result = bingsearch.parse_links(html)
                # add unique results
                new_count = 0
                for r in result:
                    if r not in urls:
                        urls.append(r)
                        new_count += 1

                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': len(result),
                    'status': "OK",
                    'status_ok': True
                })
            except HTTPError as he:
                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': 0,
                    'status': "[503] Service Unreachable: {}".format(he),
                    'status_ok': False
                })
            except URLError as ue:
                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': 0,
                    'status': "[504] Gateway Timeout: {}".format(ue),
                    'status_ok': False
                })
            except Exception as e:
                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': 0,
                    'status': "Unknown error occurred: {}".format(e),
                    'status_ok': False
                })

        return urls, pages_info

class Yahoo(Search):
    def search(self, query, pages=1):
        try:
            return yahoosearch.search(query, pages)
        except HTTPError:
            exit("[503] Service Unreachable")
        except URLError:
            exit("[504] Gateway Timeout")
        except:
            exit("Unknown error occurred")

    def search_verbose(self, query, pages=10):
        """Perform per-page Yahoo searches and return (urls, pages_info).
        Uses the Yahoo search URL format from lib/yahoo.
        """
        urls = []
        pages_info = []
        per_page = 10
        num_pages = max(1, int(math.ceil(float(pages) / per_page)))

        for i in range(num_pages):
            b = (i + 1) * 10
            request_url = "https://search.yahoo.com/search;?p={}&n={}&b={}".format(quote_plus(query), per_page, b)
            try:
                req = Request(request_url)
                # set a simple user-agent like yahoo lib does
                req.add_header("User-Agent", "yahoo search")
                resp = urlopen(req)
                html = resp.read()
                # reuse yahoo parser
                result = yahoosearch.parse_links(html)
                for r in result:
                    if r not in urls:
                        urls.append(r)

                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': len(result),
                    'status': "OK",
                    'status_ok': True
                })
            except HTTPError as he:
                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': 0,
                    'status': "[503] Service Unreachable: {}".format(he),
                    'status_ok': False
                })
            except URLError as ue:
                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': 0,
                    'status': "[504] Gateway Timeout: {}".format(ue),
                    'status_ok': False
                })
            except Exception as e:
                pages_info.append({
                    'page': i + 1,
                    'request': request_url,
                    'results': 0,
                    'status': "Unknown error occurred: {}".format(e),
                    'status_ok': False
                })

        return urls, pages_info        try:
            return bingsearch.search(query, stop=pages)
        except HTTPError:
            exit("[503] Service Unreachable")
        except URLError:
            exit("[504] Gateway Timeout")
        except:
            exit("Unknown error occurred")

class Yahoo(Search):
    def search(self, query, pages=1):
        try:
            return yahoosearch.search(query, pages)
        except HTTPError:
            exit("[503] Service Unreachable")
        except URLError:
            exit("[504] Gateway Timeout")
        except:
            exit("Unknown error occurred")
