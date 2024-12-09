import requests
from bs4 import BeautifulSoup


def is_phishing_url(url):
    try:
        response = requests.get(url, timeout=1)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        phishing_indicators = ['login', 'verify', 'account', 'bank', 'secure', 'update']

        if any(indicator in url for indicator in phishing_indicators):
            return 'Potential phishing detected'

        if any(indicator in soup.title.string.lower() for indicator in phishing_indicators if soup.title):
            return 'Potential phishing detected'

        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            if any(indicator in tag.get('content', '').lower() for indicator in phishing_indicators):
                return 'Potential phishing detected'

        return 'URL seems safe'
    except requests.RequestException:
        return 'Warning: Insecure URL'


def scan_multiple_urls(urls):
    for url in urls:
        print(f"Scanning URL: {url}")
        result = is_phishing_url(url)
        print(f"{result}: {url}")


# Example usage
urls = [
    'http://example.com/suspicious-link',
    'https://legitimate-site.com',
    'https://phishing-site.com/login',
    'https://facebook.com',
    'https://www.coursera.org/learn/ethical-hacking-essentials-ehe/home/module/1',
    'https://www.linkedin.com/'
]


if __name__ == '__main__':
    scan_multiple_urls(urls)
