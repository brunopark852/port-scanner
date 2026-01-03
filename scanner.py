#!/usr/bin/env python3
"""
Port Scanner V4.0 - AsyncIO Power
Autor: Bruno Rodrigo
"""
import asyncio
import argparse
import ipaddress
import socket
import json
import csv
import sys
import os

# --- CORES ---
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

# --- TOP 50 PORTAS (Mais comuns) ---
TOP_PORTS = list(set([
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 67, 68, 69, 123, 137, 138, 161, 
    500, 514, 520, 631, 1433, 1434, 1900, 4500, 5060, 5353, 27017, 6379, 
    8000, 8008, 8888, 9000, 9090, 8081, 3000, 5432, 2121
]))
TOP_PORTS.sort()

# --- PROBES UDP ---
UDP_PROBES = {
    53: (b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00", "DNS"),
    123: (b"\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x00"*32, "NTP"),
    161: (b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x05\x00\x05\x00", "SNMP"),
}

async def scan_tcp(ip, port, timeout, semaphore):
    async with semaphore:
        try:
            conn = asyncio.open_connection(str(ip), port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            banner = ""
            try:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner = data.decode('utf-8', 'ignore').strip().split('\n')[0]
            except: pass
            finally:
                writer.close()
                try: await writer.wait_closed()
                except: pass
            return {"ip": str(ip), "port": port, "proto": "tcp", "state": "open", "banner": banner}
        except: return None

async def scan_udp(ip, port, timeout, semaphore):
    async with semaphore:
        try:
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            payload, service_name = UDP_PROBES.get(port, (b"\x00\x00\x00\x00", "unknown"))
            await loop.sock_sendto(sock, payload, (str(ip), port))
            await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=timeout)
            sock.close()
            return {"ip": str(ip), "port": port, "proto": "udp", "state": "open", "banner": service_name}
        except:
            return None

async def run_scan(targets, ports, concurrency, timeout, no_tcp, no_udp):
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []
    
    for ip in targets:
        if not no_tcp:
            for p in ports: tasks.append(scan_tcp(ip, p, timeout, semaphore))
        if not no_udp:
            udp_ports = [p for p in ports if p in UDP_PROBES]
            for p in udp_ports: tasks.append(scan_udp(ip, p, timeout, semaphore))

    print(f"\n{Colors.BLUE}[*] Iniciando varredura em {len(targets)} alvo(s)...{Colors.RESET}")
    
    results = []
    total = len(tasks)
    done = 0
    
    for future in asyncio.as_completed(tasks):
        result = await future
        done += 1
        sys.stdout.write(f"\r{Colors.YELLOW}[~] Progresso: {done}/{total}{Colors.RESET}")
        sys.stdout.flush()
        
        if result:
            results.append(result)
            sys.stdout.write(f"\r{' '*40}\r") 
            print(f"{Colors.GREEN}[+] {result['ip']}:{result['port']}/{result['proto'].upper()} \t-> {result.get('banner') or 'unknown'}{Colors.RESET}")
            
    sys.stdout.write(f"\r{' '*40}\r")
    if not results:
        print(f"{Colors.RED}[!] Nenhuma porta aberta encontrada.{Colors.RESET}")
    else:
        print(f"{Colors.BLUE}[*] Scan finalizado. Total encontradas: {len(results)}{Colors.RESET}")
    print()
    return results

# --- UTILITÁRIOS ---
def parse_targets(inputs):
    targets = []
    if isinstance(inputs, str): inputs = [inputs]
    for i in inputs:
        try:
            if "/" in i: targets.extend([str(ip) for ip in ipaddress.IPv4Network(i, strict=False)])
            else: targets.append(str(ipaddress.IPv4Address(i)))
        except: pass
    return list(set(targets))

def save_report(results, filename):
    if not filename: return
    try:
        if filename.endswith('.csv'):
            with open(filename, 'w', newline='') as f:
                w = csv.writer(f)
                w.writerow(["IP", "Port", "Proto", "Service"])
                for r in results: w.writerow([r['ip'], r['port'], r['proto'], r.get('banner','')])
        else:
            with open(filename, 'w') as f: json.dump(results, f, indent=4)
        print(f"{Colors.GREEN}[OK] Salvo em: {filename}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}[Erro] Ao salvar arquivo: {e}{Colors.RESET}")

# --- MODO INTERATIVO (Com o BANNER BONITO) ---
def modo_interativo():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Colors.BLUE}{Colors.BOLD}")
    print(r"""
  ____   ___  ____  _____     ____   ____    _    _   _ 
 |  _ \ / _ \|  _ \|_   _|   / ___| / ___|  / \  | \ | |
 | |_) | | | | |_) | | |     \___ \| |     / _ \ |  \| |
 |  __/| |_| |  _ <  | |      ___) | |___ / ___ \| |\  |
 |_|    \___/|_| \_\ |_|     |____/ \____/_/   \_\_| \_|
                                                        
    [ Desenvolvido por: BRUNO RODRIGO ]
    """)
    print(f"{Colors.RESET}")
    
    target = input(f"{Colors.YELLOW}[?] Alvo (IP/Dominio): {Colors.RESET}")
    try:
        if not target.replace('.','').isdigit():
            target = socket.gethostbyname(target)
            print(f"{Colors.BLUE}[i] IP resolvido: {target}{Colors.RESET}")
    except:
        print(f"{Colors.RED}[!] Erro ao resolver domínio.{Colors.RESET}")
        return

    print(f"\n1. Rápido (Top 50)\n2. Normal (Top 1000)\n3. Full (Todos)\n4. Custom")
    modo = input(f"{Colors.YELLOW}[?] Opção: {Colors.RESET}")
    
    ports = TOP_PORTS
    if modo == '3': ports = list(range(1, 65536))
    elif modo == '4': 
        p = input("Portas (ex: 80,443): ")
        ports = [int(x) for x in p.split(',')]

    salvar = input(f"\n{Colors.YELLOW}[?] Salvar arquivo? (Enter para não): {Colors.RESET}")
    
    if sys.platform == 'win32': asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    results = asyncio.run(run_scan(parse_targets([target]), ports, 500, 1.0, False, False))
    if salvar: save_report(results, salvar)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        try: modo_interativo()
        except KeyboardInterrupt: print("\nSaindo...")
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("target")
        parser.add_argument("-p-", "--all", action="store_true")
        parser.add_argument("-o", "--output")
        args = parser.parse_args()
        p = list(range(1,65536)) if args.all else TOP_PORTS
        try: 
            t = socket.gethostbyname(args.target)
            results = asyncio.run(run_scan(parse_targets([t]), p, 500, 1.0, False, False))
            if args.output: save_report(results, args.output)
        except: print("Erro no alvo.")
