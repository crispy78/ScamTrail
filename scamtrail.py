import asyncio
import aiohttp
import aiodns
import whois
from urllib.parse import urlparse
from datetime import datetime, timezone
from weasyprint import HTML
import pycountry
import socket
import logging
from typing import List, Dict, Any, Optional
import os
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader
import aiofiles
import requests
from requests.exceptions import RequestException

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
MAX_REDIRECTS = int(os.getenv('MAX_REDIRECTS', 10))
PDF_OUTPUT_FILE = os.getenv('PDF_OUTPUT_FILE', 'scamtrail-report.pdf')

class URLTracer:
    def __init__(self):
        self.session = None
        self.dns_resolver = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        self.dns_resolver = aiodns.DNSResolver()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    @staticmethod
    def ensure_scheme(url: str) -> str:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            return f"https://{url}"
        return url

    @staticmethod
    def extract_domain(url: str) -> str:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(':')[0].replace('www.', '')
        return domain

    async def follow_redirects(self, url: str) -> List[str]:
        redirects = [url]
        try:
            response = await asyncio.to_thread(requests.get, url, allow_redirects=True)
            for resp in response.history:
                if resp.url != redirects[-1]:
                    redirects.append(resp.url)
            if response.url != redirects[-1]:
                redirects.append(response.url)
        except RequestException as e:
            logger.error(f"Error following redirects for {url}: {e}")
        return redirects

    async def get_whois_info(self, url: str) -> Optional[Dict[str, Any]]:
        domain = self.extract_domain(url)
        try:
            whois_info = await asyncio.to_thread(whois.whois, domain)
            return whois_info
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return None

    async def get_dns_info(self, url: str) -> Dict[str, Any]:
        domain = self.extract_domain(url)
        dns_info = {'domain': domain, 'A': [], 'NS': [], 'CNAME': []}

        for record_type in ['A', 'NS', 'CNAME']:
            try:
                if record_type == 'CNAME':
                    result = await self.dns_resolver.query(domain, 'CNAME')
                    dns_info['CNAME'] = [{'target': result.cname}]
                else:
                    result = await self.dns_resolver.query(domain, record_type)
                    if record_type == 'A':
                        dns_info['A'] = [{'ip': r.host} for r in result]
                    elif record_type == 'NS':
                        dns_info['NS'] = [{'name': r.host} for r in result]
            except aiodns.error.DNSError as e:
                logger.warning(f"DNS lookup failed for {domain} ({record_type}): {e}")

        return dns_info

    async def get_ip_address(self, url: str) -> Optional[str]:
        domain = self.extract_domain(url)
        try:
            ip_address = await asyncio.to_thread(socket.gethostbyname, domain)
            return ip_address
        except Exception as e:
            logger.error(f"IP lookup failed for {domain}: {e}")
            return None

    async def reverse_dns_lookup(self, ip_address: str) -> Optional[List[str]]:
        try:
            hostnames = await asyncio.to_thread(socket.gethostbyaddr, ip_address)
            return hostnames[1]
        except Exception as e:
            logger.error(f"Reverse DNS lookup failed for {ip_address}: {e}")
            return None

    @staticmethod
    def calculate_domain_age(creation_date: Optional[datetime]) -> str:
        if not creation_date:
            return "Unknown"
        
        now = datetime.now(timezone.utc)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        # Ensure creation_date is timezone-aware
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        
        delta = now - creation_date
        years, remaining_days = divmod(delta.days, 365)
        months, days = divmod(remaining_days, 30)
        
        return f"{years} years, {months} months, {days} days"

    async def get_ip_geolocation(self, ip_address: str) -> str:
        try:
            headers = {
                "User-Agent": "ScamTrail/1.0",
                "Accept": "application/json"
            }
            async with self.session.get(f"http://ip-api.com/json/{ip_address}", headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    city = data.get('city', 'Unknown')
                    region = data.get('regionName', 'Unknown')
                    country = data.get('country', 'Unknown')
                    return f"{city}, {region}, {country}"
                else:
                    response_text = await response.text()
                    logger.error(f"Failed to get geolocation for {ip_address}. Status code: {response.status}, Response: {response_text}")
                    return "Unknown, Unknown, Unknown"
        except Exception as e:
            logger.error(f"Geolocation lookup failed for {ip_address}: {e}")
            return "Unknown, Unknown, Unknown"

    async def is_cloudflare_domain(self, domain: str) -> bool:
        try:
            ns_records = await self.dns_resolver.query(domain, 'NS')
            cloudflare_ns_suffixes = ['cloudflare.com', '.cloudflare.com']
            for ns in ns_records:
                ns_text = ns.host.lower().rstrip('.')
                if any(ns_text.endswith(suffix) for suffix in cloudflare_ns_suffixes):
                    return True
            return False
        except aiodns.error.DNSError as e:
            logger.warning(f"DNS lookup failed for {domain} when checking Cloudflare usage: {e}")
            return False
        except Exception as e:
            logger.error(f"Error checking Cloudflare usage for {domain}: {e}")
            return False

class ReportGenerator:
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader('templates'))
        self.template = self.env.get_template('report_template.html')

    async def generate_report(self, data: Dict[str, Any]) -> None:
        html_content = self.template.render(data)
        
        async with aiofiles.open('report.html', 'w') as f:
            await f.write(html_content)

        # Convert HTML to PDF using WeasyPrint
        HTML('report.html').write_pdf(PDF_OUTPUT_FILE)
        logger.info(f"Report saved to {PDF_OUTPUT_FILE}")

async def main():
    url = input("Enter the URL to trace: ").strip()
    
    async with URLTracer() as tracer:
        url = URLTracer.ensure_scheme(url)
        redirects = await tracer.follow_redirects(url)
        final_url = redirects[-1]

        tasks = []
        for redirect in redirects:
            tasks.append(tracer.get_whois_info(redirect))
            tasks.append(tracer.get_dns_info(redirect))
            tasks.append(tracer.get_ip_address(redirect))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        whois_infos = [r if not isinstance(r, Exception) else None for r in results[0::3]]
        dns_infos = [r if not isinstance(r, Exception) else None for r in results[1::3]]
        ip_addresses = [r if not isinstance(r, Exception) else None for r in results[2::3]]

        # Process results
        cloudflare_info = {}
        reverse_dns_info = {}
        ip_geolocations = {}

        for url, ip in zip(redirects, ip_addresses):
            if ip:
                domain = URLTracer.extract_domain(url)
                cloudflare_info[domain] = await tracer.is_cloudflare_domain(domain)
                reverse_dns = await tracer.reverse_dns_lookup(ip)
                reverse_dns_info[ip] = reverse_dns if reverse_dns else []
                geolocation = await tracer.get_ip_geolocation(ip)
                ip_geolocations[ip] = geolocation
                logger.info(f"URL: {url}, IP: {ip}, Geolocation: {geolocation}")

        # Prepare data for report
        report_data = {
            'redirects': redirects,
            'whois_infos': [{'domain': URLTracer.extract_domain(url), 'info': info} for url, info in zip(redirects, whois_infos)],
            'dns_infos': [info for info in dns_infos if info is not None],
            'ip_addresses': ip_addresses,
            'final_url': final_url,
            'cloudflare_info': cloudflare_info,
            'reverse_dns_info': reverse_dns_info,
            'ip_geolocations': ip_geolocations,
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
            'domain_age': URLTracer.calculate_domain_age(whois_infos[0].get('creation_date') if whois_infos[0] else None),
            'uses_cloudflare': cloudflare_info.get(URLTracer.extract_domain(final_url), False)
        }

        # Generate report
        report_generator = ReportGenerator()
        await report_generator.generate_report(report_data)

        # Print out the key information
        print(f"The destination of the URL you've entered ({url}) is {final_url}")
        print(f"It used {len(redirects) - 1} redirects to get to its destination.")
        print(f"The domain has been registered for {report_data['domain_age']}.")
        
        final_ip = ip_addresses[-1] if ip_addresses else None
        if final_ip and final_ip in ip_geolocations:
            print(f"The geographical location of the site is {ip_geolocations[final_ip]}.")
        else:
            print("Unable to determine the geographical location of the site.")
        
        print(f"The site {"uses" if report_data['uses_cloudflare'] else "doesn't use"} CloudFlare for obfuscation or protection.")

if __name__ == "__main__":
    asyncio.run(main())
