import csv
import socket
import time
from tqdm import tqdm

def get_asn_info(ip):
    try:
        whois_server = 'whois.cymru.com'
        port = 43
        
        # "-v" per avere l'output formattato con riga di header + riga di dati
        query = f" -v {ip}\r\n"
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((whois_server, port))
            s.send(query.encode())
            response = s.recv(4096).decode()
        
        # Pulizia delle righe (eliminiamo vuoti, righe bianche, ecc.)
        lines = [l.strip() for l in response.splitlines() if l.strip()]
        
        # La prima riga (lines[0]) di solito è un header es: "AS | IP | BGP Prefix | ..."
        # La seconda riga (lines[1]) dovrebbe contenere i dati
        if len(lines) < 2:
            return ip, 'N/A', 'N/A'
        
        data_line = lines[1]
        parts = data_line.split('|')
        if len(parts) < 7:
            return ip, 'N/A', 'N/A'
        
        asn = parts[0].strip()
        as_name = parts[6].strip()
        
        return ip, asn, as_name

    except Exception as e:
        print(f"Errore nella query Whois per {ip}: {e}")
        return ip, 'N/A', 'N/A'


def process_ips(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        ip_list = infile.readlines()
        
        # Qui usiamo il punto e virgola come separatore
        writer = csv.writer(outfile, delimiter=';')
        
        # Intestazione
        writer.writerow(['IP', 'ASN', 'AS Name'])
        
        for line in tqdm(ip_list, desc="Elaborazione IPs", unit="IP"):
            ip = line.strip()
            if ip:
                # Ottieni informazioni ASN
                ip_out, asn, as_name = get_asn_info(ip)
                writer.writerow([ip_out, asn, as_name])
                
                # Pausa di 7 secondi
                time.sleep(1)


if __name__ == "__main__":
    input_file = 'ips.txt'
    output_file = 'result.csv'
    process_ips(input_file, output_file)
