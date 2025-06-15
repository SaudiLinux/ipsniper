#!/usr/bin/env python3
import requests
import whois
import dns.resolver
import socket
import json
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

def print_banner():
    banner = f'''
    {Fore.RED}{Style.BRIGHT}
    ╔══════════════════════════════════════════════════════════════════════╗
    ║  ██╗██████╗     ███████╗███╗   ██╗██╗██████╗ ███████╗██████╗      ║
    ║  ██║██╔══██╗    ██╔════╝████╗  ██║██║██╔══██╗██╔════╝██╔══██╗     ║
    ║  ██║██████╔╝    ███████╗██╔██╗ ██║██║██████╔╝█████╗  ██████╔╝     ║
    ║  ██║██╔═══╝     ╚════██║██║╚██╗██║██║██╔═══╝ ██╔══╝  ██╔══██╗     ║
    ║  ██║██║         ███████║██║ ╚████║██║██║     ███████╗██║  ██║     ║
    ║  ╚═╝╚═╝         ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝     ║
    ╚══════════════════════════════════════════════════════════════════════╝
    {Style.RESET_ALL}
    {Fore.RED}{Style.BRIGHT}By: Saudi Linux{Style.RESET_ALL}
    {Fore.RED}{Style.BRIGHT}Email: SaudiCrackers@gmail.com{Style.RESET_ALL}
    '''
    print(banner)

def get_ip_info(target):
    try:
        # التحقق مما إذا كان الهدف IP أو دومين
        try:
            ip = socket.gethostbyname(target)
        except:
            print(f'{Fore.RED}[!] خطأ في الحصول على عنوان IP{Style.RESET_ALL}')
            return None

        # الحصول على معلومات IP
        response = requests.get(f'http://ip-api.com/json/{ip}')
        if response.status_code == 200:
            data = response.json()
            return {
                'ip': ip,
                'country': data.get('country', 'غير معروف'),
                'region': data.get('regionName', 'غير معروف'),
                'city': data.get('city', 'غير معروف'),
                'isp': data.get('isp', 'غير معروف'),
                'org': data.get('org', 'غير معروف'),
                'as': data.get('as', 'غير معروف'),
                'timezone': data.get('timezone', 'غير معروف')
            }
    except Exception as e:
        print(f'{Fore.RED}[!] خطأ في الحصول على معلومات IP: {str(e)}{Style.RESET_ALL}')
        return None

def get_domain_info(domain):
    try:
        w = whois.whois(domain)
        return {
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'name_servers': w.name_servers,
            'status': w.status,
            'emails': w.emails
        }
    except Exception as e:
        print(f'{Fore.RED}[!] خطأ في الحصول على معلومات الدومين: {str(e)}{Style.RESET_ALL}')
        return None

def get_dns_info(domain):
    try:
        records = {}
        record_types = ['A', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except:
                continue
        
        return records
    except Exception as e:
        print(f'{Fore.RED}[!] خطأ في الحصول على معلومات DNS: {str(e)}{Style.RESET_ALL}')
        return None

def check_common_vulnerabilities(target):
    vulnerabilities = []
    try:
        # فحص منافذ شائعة
        common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389]
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                vulnerabilities.append(f'المنفذ {port} مفتوح')
            sock.close()

        # فحص HTTPS
        try:
            response = requests.get(f'https://{target}', verify=True)
        except requests.exceptions.SSLError:
            vulnerabilities.append('شهادة SSL غير صالحة أو غير موجودة')
        except:
            pass

        return vulnerabilities
    except Exception as e:
        print(f'{Fore.RED}[!] خطأ في فحص الثغرات: {str(e)}{Style.RESET_ALL}')
        return None

def save_results(target, results):
    filename = f'{target}_scan_results.json'
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=4, default=str)
        print(f'\n{Fore.GREEN}[+] تم حفظ النتائج في الملف: {filename}{Style.RESET_ALL}')
    except Exception as e:
        print(f'{Fore.RED}[!] خطأ في حفظ النتائج: {str(e)}{Style.RESET_ALL}')

def print_results(results):
    print(f'\n{Fore.YELLOW}=== نتائج الفحص ==={Style.RESET_ALL}')

    # طباعة معلومات IP
    if results.get('ip_info'):
        print(f'\n{Fore.CYAN}معلومات IP:{Style.RESET_ALL}')
        for key, value in results['ip_info'].items():
            print(f'{Fore.GREEN}{key}: {Style.RESET_ALL}{value}')

    # طباعة معلومات الدومين
    if results.get('domain_info'):
        print(f'\n{Fore.CYAN}معلومات الدومين:{Style.RESET_ALL}')
        for key, value in results['domain_info'].items():
            print(f'{Fore.GREEN}{key}: {Style.RESET_ALL}{value}')

    # طباعة معلومات DNS
    if results.get('dns_info'):
        print(f'\n{Fore.CYAN}معلومات DNS:{Style.RESET_ALL}')
        for record_type, records in results['dns_info'].items():
            print(f'{Fore.GREEN}{record_type}:{Style.RESET_ALL}')
            for record in records:
                print(f'  {record}')

    # طباعة الثغرات المحتملة
    if results.get('vulnerabilities'):
        print(f'\n{Fore.CYAN}الثغرات المحتملة:{Style.RESET_ALL}')
        for vuln in results['vulnerabilities']:
            print(f'{Fore.RED}[!] {vuln}{Style.RESET_ALL}')

def main():
    print_banner()
    target = input(f'{Fore.CYAN}أدخل عنوان IP أو اسم النطاق للفحص: {Style.RESET_ALL}')
    
    if not target.strip():
        print(f'{Fore.RED}[!] يجب إدخال هدف للفحص!{Style.RESET_ALL}')
        return

    print(f'\n{Fore.YELLOW}[*] جاري فحص الهدف: {target}{Style.RESET_ALL}')
    
    results = {
        'target': target,
        'scan_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    # جمع المعلومات
    results['ip_info'] = get_ip_info(target)
    if '.' in target and not target.replace('.', '').isdigit():
        results['domain_info'] = get_domain_info(target)
        results['dns_info'] = get_dns_info(target)
    results['vulnerabilities'] = check_common_vulnerabilities(target)

    # عرض وحفظ النتائج
    print_results(results)
    save_results(target, results)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f'\n{Fore.RED}[!] تم إيقاف الفحص بواسطة المستخدم{Style.RESET_ALL}')
    except Exception as e:
        print(f'\n{Fore.RED}[!] حدث خطأ: {str(e)}{Style.RESET_ALL}')