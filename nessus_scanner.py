#!/usr/bin/env python3
import requests
import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class NessusScanner:
    def __init__(self, url, access_key, secret_key):
        self.url = url.rstrip('/')
        self.headers = {
            'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
            'Content-Type': 'application/json'
        }

    def print_banner(self):
        banner = f'''
        {Fore.RED}{Style.BRIGHT}
        ╔═══════════════════════════════════════════════════════════════════════╗
        ║  ███╗   ██╗███████╗███████╗███████╗██╗   ██╗███████╗               ║
        ║  ████╗  ██║██╔════╝██╔════╝██╔════╝██║   ██║██╔════╝               ║
        ║  ██╔██╗ ██║█████╗  ███████╗███████╗██║   ██║███████╗               ║
        ║  ██║╚██╗██║██╔══╝  ╚════██║╚════██║██║   ██║╚════██║               ║
        ║  ██║ ╚████║███████╗███████║███████║╚██████╔╝███████║               ║
        ║  ╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚══════╝               ║
        ║                     ███████╗ ██████╗ █████╗ ███╗   ██╗             ║
        ║                     ██╔════╝██╔════╝██╔══██╗████╗  ██║             ║
        ║                     ███████╗██║     ███████║██╔██╗ ██║             ║
        ║                     ╚════██║██║     ██╔══██║██║╚██╗██║             ║
        ║                     ███████║╚██████╗██║  ██║██║ ╚████║             ║
        ║                     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝             ║
        ╚═══════════════════════════════════════════════════════════════════════╝
        {Style.RESET_ALL}
        {Fore.RED}{Style.BRIGHT}By: Saudi Linux{Style.RESET_ALL}
        {Fore.RED}{Style.BRIGHT}Email: SaudiCrackers@gmail.com{Style.RESET_ALL}
        '''
        print(banner)

    def test_connection(self):
        try:
            response = requests.get(f'{self.url}/server/status', headers=self.headers, verify=False)
            return response.status_code == 200
        except Exception as e:
            print(f'{Fore.RED}[!] خطأ في الاتصال: {str(e)}{Style.RESET_ALL}')
            return False

    def create_scan(self, name, targets, template_id='basic'):
        try:
            scan_data = {
                'uuid': template_id,
                'settings': {
                    'name': name,
                    'text_targets': targets
                }
            }

            response = requests.post(
                f'{self.url}/scans',
                headers=self.headers,
                json=scan_data,
                verify=False
            )

            if response.status_code == 200:
                return response.json()['scan']['id']
            else:
                print(f'{Fore.RED}[!] خطأ في إنشاء الفحص: {response.text}{Style.RESET_ALL}')
                return None

        except Exception as e:
            print(f'{Fore.RED}[!] خطأ في إنشاء الفحص: {str(e)}{Style.RESET_ALL}')
            return None

    def launch_scan(self, scan_id):
        try:
            response = requests.post(
                f'{self.url}/scans/{scan_id}/launch',
                headers=self.headers,
                verify=False
            )

            if response.status_code == 200:
                return True
            else:
                print(f'{Fore.RED}[!] خطأ في بدء الفحص: {response.text}{Style.RESET_ALL}')
                return False

        except Exception as e:
            print(f'{Fore.RED}[!] خطأ في بدء الفحص: {str(e)}{Style.RESET_ALL}')
            return False

    def get_scan_status(self, scan_id):
        try:
            response = requests.get(
                f'{self.url}/scans/{scan_id}',
                headers=self.headers,
                verify=False
            )

            if response.status_code == 200:
                return response.json()['info']['status']
            else:
                print(f'{Fore.RED}[!] خطأ في الحصول على حالة الفحص: {response.text}{Style.RESET_ALL}')
                return None

        except Exception as e:
            print(f'{Fore.RED}[!] خطأ في الحصول على حالة الفحص: {str(e)}{Style.RESET_ALL}')
            return None

    def get_scan_results(self, scan_id):
        try:
            response = requests.get(
                f'{self.url}/scans/{scan_id}',
                headers=self.headers,
                verify=False
            )

            if response.status_code == 200:
                return response.json()
            else:
                print(f'{Fore.RED}[!] خطأ في الحصول على نتائج الفحص: {response.text}{Style.RESET_ALL}')
                return None

        except Exception as e:
            print(f'{Fore.RED}[!] خطأ في الحصول على نتائج الفحص: {str(e)}{Style.RESET_ALL}')
            return None

    def save_results(self, results, filename=None):
        if filename is None:
            filename = f'nessus_scan_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=4)
            print(f'\n{Fore.GREEN}[+] تم حفظ النتائج في الملف: {filename}{Style.RESET_ALL}')
        except Exception as e:
            print(f'{Fore.RED}[!] خطأ في حفظ النتائج: {str(e)}{Style.RESET_ALL}')

def main():
    scanner = NessusScanner(
        url='https://localhost:8834',  # تغيير هذا إلى عنوان خادم Nessus الخاص بك
        access_key='your-access-key',  # تغيير هذا إلى مفتاح الوصول الخاص بك
        secret_key='your-secret-key'   # تغيير هذا إلى المفتاح السري الخاص بك
    )

    scanner.print_banner()

    if not scanner.test_connection():
        print(f'{Fore.RED}[!] فشل الاتصال بخادم Nessus{Style.RESET_ALL}')
        return

    target = input(f'{Fore.CYAN}أدخل الهدف للفحص (IP أو نطاق): {Style.RESET_ALL}')
    scan_name = input(f'{Fore.CYAN}أدخل اسم الفحص: {Style.RESET_ALL}')

    print(f'\n{Fore.YELLOW}[*] جاري إنشاء الفحص...{Style.RESET_ALL}')
    scan_id = scanner.create_scan(scan_name, target)

    if scan_id:
        print(f'{Fore.GREEN}[+] تم إنشاء الفحص بنجاح (ID: {scan_id}){Style.RESET_ALL}')
        print(f'\n{Fore.YELLOW}[*] جاري بدء الفحص...{Style.RESET_ALL}')

        if scanner.launch_scan(scan_id):
            print(f'{Fore.GREEN}[+] تم بدء الفحص بنجاح{Style.RESET_ALL}')

            while True:
                status = scanner.get_scan_status(scan_id)
                if status == 'completed':
                    print(f'\n{Fore.GREEN}[+] اكتمل الفحص{Style.RESET_ALL}')
                    results = scanner.get_scan_results(scan_id)
                    if results:
                        scanner.save_results(results)
                    break
                elif status == 'running':
                    print(f'{Fore.YELLOW}[*] جاري الفحص...{Style.RESET_ALL}')
                else:
                    print(f'{Fore.RED}[!] حالة الفحص: {status}{Style.RESET_ALL}')
                    break

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f'\n{Fore.RED}[!] تم إيقاف البرنامج بواسطة المستخدم{Style.RESET_ALL}')
    except Exception as e:
        print(f'\n{Fore.RED}[!] حدث خطأ: {str(e)}{Style.RESET_ALL}')