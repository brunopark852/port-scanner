# ⚡ Port Scanner V4.0 (AsyncIO)

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![AsyncIO](https://img.shields.io/badge/Tech-AsyncIO-green?style=for-the-badge)

Ferramenta de varredura de portas (Port Scanner) de alta performance desenvolvida em Python. Diferente de scanners tradicionais que usam *Threading* (que pesam a CPU), esta ferramenta utiliza **AsyncIO** (biblioteca de processamento assíncrono) para testar milhares de conexões simultâneas de forma leve e extremamente rápida.

## 🚀 Funcionalidades

* **[+] Alta Performance:** Escaneia milhares de portas em segundos usando concorrência assíncrona.
* **[+] Modo Interativo:** Menu visual para facilitar o uso sem decorar comandos.
* **[+] Banner Grabbing:** Tenta identificar qual serviço está rodando na porta (SSH, Apache, etc).
* **[+] UDP Probes:** Envia payloads específicos para detectar serviços UDP (DNS, NTP, SNMP).
* **[+] Relatórios:** Salva os resultados em JSON ou CSV.

## 🛠️ Instalação

```bash
# 1. Clone o repositório
git clone [https://github.com/brunopark852/port-scanner.git](https://github.com/brunopark852/port-scanner.git)

# 2. Entre na pasta
cd port-scanner

# 3. Execute (Não requer pip install de libs externas!)
💻 Como Usar

Modo Interativo (Recomendado): Basta rodar o script sem argumentos:
Bash

python3 scanner.py

Ele irá perguntar o alvo e o tipo de scan (Rápido, Full, Custom).

Modo CLI (Linha de Comando):
Bash

# Scan completo em um alvo
python3 scanner.py 192.168.0.1 -p-

# Scan salvando em arquivo
python3 scanner.py google.com -o resultado.json

⚠️ Disclaimer

Esta ferramenta foi criada para fins de estudo e uso em redes autorizadas. O desenvolvedor não se responsabiliza pelo uso indevido.
Dev: Bruno Rodrigo 💀
python3 scanner.py
