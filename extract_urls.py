import re
import sys
from urllib.parse import urljoin
from bs4 import BeautifulSoup

def extract_urls(html_file, base_url=None):
    """Extract all URLs from an HTML file."""
    with open(html_file, 'r', encoding='utf-8') as f:
        html_content = f.read()

    soup = BeautifulSoup(html_content, 'html.parser')
    urls = set()

    # Extract from href attributes
    for tag in soup.find_all(href=True):
        url = tag['href']
        if base_url:
            url = urljoin(base_url, url)
        urls.add(url)

    # Extract from src attributes
    for tag in soup.find_all(src=True):
        url = tag['src']
        if base_url:
            url = urljoin(base_url, url)
        urls.add(url)

    # Extract from data-src, data-href, etc.
    for tag in soup.find_all(True):
        for attr in ['data-src', 'data-href', 'data-url', 'data-link']:
            if tag.get(attr):
                url = tag[attr]
                if base_url:
                    url = urljoin(base_url, url)
                urls.add(url)

    # Extract URLs from inline styles (background-image, etc.)
    style_urls = re.findall(r'url\(["\']?([^"\')]+)["\']?\)', html_content)
    for url in style_urls:
        if base_url:
            url = urljoin(base_url, url)
        urls.add(url)

    return sorted(urls)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python extract_urls.py <html_file> [base_url]")
        sys.exit(1)

    html_file = sys.argv[1]
    base_url = sys.argv[2] if len(sys.argv) > 2 else None

    urls = extract_urls(html_file, base_url)
    for url in urls:
        print(url)