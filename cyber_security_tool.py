import re
import colorama
from colorama import Fore, Style
import ipaddress
import socket
import ssl
import requests
import smtplib
import subprocess
import scapy.all as scapy
import datetime
import os
import random
import string
import hashlib
from getpass import getpass
from time import sleep

colorama.init(autoreset=True)

# Log dosyası
log_file = "security_log.txt"

def log_to_file(message):
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            f.write("Siber Güvenlik Aracı Log Kayıtları\n")
            f.write("===============================\n")
    with open(log_file, 'a') as f:
        f.write(f"{datetime.datetime.now()} - {message}\n")

# IP Adresi Analizi
def analyze_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        ip_type = "Özel" if ip_obj.is_private else "Genel"
        additional_info = []

        if ip_obj.is_multicast:
            additional_info.append("Multicast")
        if ip_obj.is_loopback:
            additional_info.append("Loopback")
        if ip_obj.is_reserved:
            additional_info.append("Rezerve Edilmiş")

        info_str = ", ".join(additional_info) if additional_info else "Yok"
        
        log_to_file(f"IP Analizi: {ip} ({ip_type})")
        return (f"{Fore.GREEN}IP Adresi Geçerli: {ip}\n"
                f"IP Türü: {ip_type}\n"
                f"Ek Bilgiler: {info_str}")
    except ValueError:
        log_to_file(f"Geçersiz IP: {ip}")
        return f"{Fore.RED}Geçersiz IP adresi! Lütfen doğru bir IP adresi girin."

# Web Uygulama Güvenliği Tarama (Nikto)
def web_security_scan(domain):
    try:
        result = subprocess.run(['nikto', '-h', domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode()
    except Exception as e:
        return f"{Fore.RED}Web güvenlik taraması sırasında hata oluştu: {str(e)}"

# Phishing Testi (Simülasyon)
def phishing_test():
    phishing_urls = [
        "http://example.com/fake-login",
        "http://example2.com/steal-password"
    ]
    print(f"{Fore.YELLOW}Sahte Phishing bağlantıları (test):")
    for url in phishing_urls:
        print(f"- {url}")

# Shodan Taraması (IP Cihaz Tespiti)
def shodan_scan(ip):
    try:
        api_key = 'your-shodan-api-key'
        response = requests.get(f'https://api.shodan.io/shodan/host/{ip}?key={api_key}')
        data = response.json()
        if 'data' in data:
            return f"{Fore.GREEN}Shodan Tarama Sonuçları: {data['data']}"
        else:
            return f"{Fore.RED}Cihaz bulunamadı."
    except requests.RequestException as e:
        return f"{Fore.RED}Shodan taraması sırasında hata oluştu: {str(e)}"

# Sosyal Mühendislik E-posta Testi
def social_engineering_email():
    phishing_email = "phishing@example.com"
    print(f"{Fore.YELLOW}Potansiyel phishing e-postası: {phishing_email}")
    print(f"{Fore.YELLOW}E-posta adresini doğrulamak için test yapılabilir.")

# Ağ Taraması (Scapy Kullanarak)
def network_scan(ip_range):
    # ARP isteği göndererek ağdaki cihazları tarıyoruz
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Yanıtları alıyoruz
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})

    return devices

def display_results(devices):
    print("IP Adresi\t\tMAC Adresi")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

# Ana Menü
def main():
    print(f"{Fore.CYAN}Siber Güvenlik Aracına Hoş Geldiniz!{Style.RESET_ALL}")

    while True:
        print(f"\n{Fore.YELLOW}1. IP Analizi\n2. Web Güvenlik Taraması\n3. Phishing Testi\n4. Shodan Tarama\n5. Şifre Güvenliği Testi\n6. Ağ Taraması\n7. Çıkış{Style.RESET_ALL}")
        choice = input("Seçiminizi yapın: ")

        if choice == "1":
            ip = input("IP adresini girin: ")
            print(analyze_ip(ip))

        elif choice == "2":
            domain = input("Web sitesinin domain adını girin: ")
            print(web_security_scan(domain))

        elif choice == "3":
            phishing_test()

        elif choice == "4":
            ip = input("Shodan taraması yapılacak IP adresini girin: ")
            print(shodan_scan(ip))

        elif choice == "5":
            password = getpass("Şifrenizi girin (gizli giriş): ")
            print(analyze_password(password))

        elif choice == "6":
            ip_range = input("Ağ taraması yapılacak IP aralığını girin (örneğin: 192.168.1.0/24): ")
            devices = network_scan(ip_range)
            display_results(devices)

        elif choice == "7":
            print(f"{Fore.CYAN}Çıkış yapılıyor. Güvenli günler dileriz!{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Geçersiz seçim. Lütfen tekrar deneyin.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
