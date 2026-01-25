from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from attacks.runners import docker_run_detached

@dataclass(frozen=True)
class ParamSpec:
    key: str
    label: str
    kind: str  # "ip" | "port" | "cidr" | "text"
    placeholder: Optional[str] = None
    default: Optional[Any] = None

@dataclass(frozen=True)
class AttackSpec:
    id: str
    name: str
    description: str
    image: str
    container_name: str
    params: List[ParamSpec] = field(default_factory=list)
    no_params_note: Optional[str] = None
    details_warning: Optional[str] = None
    mitre: Optional[str] = None


    def runner(self, resolved_params: Dict[str, Any]) -> Dict[str, Any]:
        # A ordem dos args segue a ordem dos ParamSpec
        args = [str(resolved_params[p.key]) for p in self.params]
        return docker_run_detached(
            image=self.image,
            name=self.container_name,
            args=args,
        )

def A(
    *,
    id: str,
    name: str,
    description: str,
    image_base: str,
    params: Optional[List[ParamSpec]] = None,
    no_params_note: Optional[str] = None,
    details_warning: Optional[str] = None,
    mitre: Optional[str] = None,
) -> AttackSpec:
    """
    Helper: padroniza image/container_name baseado no image_base informado.
    """
    return AttackSpec(
        id=id,
        name=name,
        description=description,
        image=f"{image_base}:latest",
        container_name=image_base,  # nome do container = base
        params=params or [],
        no_params_note=no_params_note,
        details_warning=details_warning,
        mitre=mitre,
    )


# Categorias em abas
CATEGORIES: Dict[str, List[AttackSpec]] = {
    "1) Ataques de Aplicação Web": [
        A(
            id="web_idor_path_traversal",
            name="IDOR Path Traversal",
            description="Ataque IDOR via path traversal.",
            image_base="sbrc26-ataque-idor-path-traversal",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            mitre=("https://attack.mitre.org/techniques/T1420/"),
        ),
        A(
            id="web_idor_url_parameter",
            name="IDOR URL Parameter",
            description="Ataque IDOR via parâmetro de URL.",
            image_base="sbrc26-ataque-idor-url-parameter",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            mitre=("https://attack.mitre.org/techniques/T1595/003/"),
        ),
        A(
            id="php_lfi_enumeration",
            name="PHP LFI Enumeration",
            description="Ataque de enumeração de Local File Inclusion.",
            image_base="sbrc26-ataque-php-lfi-enumeration",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            mitre=("https://attack.mitre.org/techniques/T1595/003/"),
        ),
        A(
            id="web_sql_injection",
            name="SQL Injection",
            description="Teste/exploração de SQL injection.",
            image_base="sbrc26-ataque-sql-injection",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
        ),
        A(
            id="web_dir_enumeration",
            name="Enumeração de diretórios",
            description="Enumeração de paths e recursos web.",
            image_base="sbrc26-ataque-web-dir-enumeration",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="web_https_heartbleed",
            name="HTTPS Heartbleed",
            description="Scanner/exploração Heartbleed sobre HTTPS.",
            image_base="sbrc26-ataque-web-https-heartbleed",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8443", default=8443),
            ],
        ),
        A(
            id="web_post_bruteforce",
            name="Web POST Bruteforce",
            description="Força bruta via POST em aplicação web.",
            image_base="sbrc26-ataque-web-post-bruteforce",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="web_simple_scanner",
            name="Web Simple Scanner",
            description="Scanner web simples.",
            image_base="sbrc26-ataque-web-simple-scanner",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
        ),
        A(
            id="web_wide_scanner",
            name="Web Wide Scanner",
            description="Scanner web mais amplo.",
            image_base="sbrc26-ataque-web-wide-scanner",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="web_xss_scanner",
            name="XSS Scanner",
            description="Scanner de XSS.",
            image_base="sbrc26-ataque-xss-scanner",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
        ),
    ],

    "2) Força Bruta": [
        A(
            id="bf_ssh",
            name="SSH Bruteforce",
            description="Força bruta em SSH.",
            image_base="sbrc26-ataque-ssh-bruteforce",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="2222", default=2222),
            ],
        ),
        A(
            id="bf_telnet",
            name="Telnet Bruteforce",
            description="Força bruta em Telnet.",
            image_base="sbrc26-ataque-telnet-bruteforce",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="2323", default=2323),
            ],
        ),
    ],

    "3) Protocolos IoT": [
        A(
            id="iot_coap_get_flood",
            name="CoAP GET Flood",
            description="Flood de requisições GET em CoAP.",
            image_base="sbrc26-ataque-coap-get-flood",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
        ),
        A(
            id="iot_mqtt_bruteforce",
            name="MQTT Bruteforce",
            description="Força bruta MQTT.",
            image_base="sbrc26-ataque-mqtt-bruteforce",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
        ),
        A(
            id="iot_mqtt_publisher",
            name="MQTT Publisher",
            description="Publicação de mensagens MQTT.",
            image_base="sbrc26-ataque-mqtt-publisher",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
        ),
    ],

    "4) DoS e Impacto": [
        A(
            id="dos_http_simple",
            name="DoS HTTP Simple",
            description="DoS simples na aplicação HTTP.",
            image_base="sbrc26-ataque-dos-http-simple",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
        ),
        A(
            id="dos_http_slowloris",
            name="DoS HTTP Slowloris",
            description="DoS Slowloris na aplicação HTTP.",
            image_base="sbrc26-ataque-dos-http-slowloris",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
        ),
        A(
            id="dos_fin_flood",
            name="FIN Flood",
            description="Flood FIN.",
            image_base="sbrc26-ataque-fin-flood",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="dos_icmp_flood",
            name="ICMP Flood",
            description="Flood ICMP no alvo.",
            image_base="sbrc26-ataque-icmp-flood",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="dos_psh_flood",
            name="PSH Flood",
            description="Flood PSH.",
            image_base="sbrc26-ataque-psh-flood",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="dos_rst_flood",
            name="RST Flood",
            description="Flood RST.",
            image_base="sbrc26-ataque-rst-flood",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="dos_syn_flood",
            name="SYN Flood",
            description="Flood SYN.",
            image_base="sbrc26-ataque-syn-flood",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="dos_udp_flood",
            name="UDP Flood",
            description="Flood UDP.",
            image_base="sbrc26-ataque-udp-flood",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="8080", default=8080),
            ],
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
    ],

    "5) Reconhecimento / Descoberta": [
        A(
            id="recon_arp_scan",
            name="ARP Scan",
            description="Enumeração de hosts via ARP na rede alvo.",
            image_base="sbrc26-ataque-arp-scan",
            params=[ParamSpec("target_net", "Rede alvo", "cidr", placeholder="192.168.0.0/24")],
        ),
        A(
            id="recon_ping_sweep",
            name="Ping Sweep",
            description="Varredura ICMP para descoberta de hosts.",
            image_base="sbrc26-ataque-ping-sweep",
            params=[ParamSpec("target_net", "Rede alvo", "cidr", placeholder="192.168.0.0/24")],
        ),
        A(
            id="recon_port_scanner_aggressive",
            name="Port Scanner Aggressive",
            description="Varredura de portas/serviços com perfil agressivo.",
            image_base="sbrc26-ataque-port-scanner-aggressive",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
        ),
        A(
            id="recon_port_scanner_os",
            name="Port Scanner OS",
            description="Detecção de SO (fingerprinting) do alvo.",
            image_base="sbrc26-ataque-port-scanner-os",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
        ),
        A(
            id="recon_port_scanner_tcp",
            name="Port Scanner TCP",
            description="Varredura TCP do alvo.",
            image_base="sbrc26-ataque-port-scanner-tcp",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
        ),
        A(
            id="recon_port_scanner_udp",
            name="Port Scanner UDP",
            description="Varredura UDP do alvo.",
            image_base="sbrc26-ataque-port-scanner-udp",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
        ),
        A(
            id="recon_port_scanner_vuln",
            name="Port Scanner Vulnerabilities",
            description="Varredura + checagens de vulnerabilidades.",
            image_base="sbrc26-ataque-port-scanner-vulnerabilities",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
        ),
        A(
            id="recon_smb_enum",
            name="SMB Enumerating",
            description="Enumeração SMB.",
            image_base="sbrc26-ataque-smb-enumerating",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
        ),
        A(
            id="recon_snmp_scanner",
            name="SNMP Scanner",
            description="Scanner/enumeração SNMP.",
            image_base="sbrc26-ataque-snmp-scanner",
            params=[ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__")],
        ),
    ],

    "6) Interceptação / Exploração de Rede": [
        A(
            id="net_arp_spoof",
            name="ARP Spoof",
            description="Ataque de interceptação via ARP spoofing.",
            image_base="sbrc26-ataque-arp-spoof",
            params=[
                ParamSpec("target_net", "Rede alvo", "cidr", placeholder="192.168.0.0/24"),
                ParamSpec("spoof_gw", "Spoofed Gateway", "ip", placeholder="192.168.0.1"),
            ],
        ),
        A(
            id="net_cdp_table_flood",
            name="CDP Table Flood",
            description="Flood de CDP table em rede local.",
            image_base="sbrc26-ataque-cdp-table-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="net_dhcp_starvation",
            name="DHCP Starvation",
            description="Exaustão de leases DHCP em rede local.",
            image_base="sbrc26-ataque-dhcp-starvation",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
        ),
        A(
            id="net_stp_conf_flood",
            name="STP Config Flood",
            description="Flood de configuração STP em rede local.",
            image_base="sbrc26-ataque-stp-conf-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="net_stp_tcn_flood",
            name="STP TCN Flood",
            description="Flood de TCN STP em rede local.",
            image_base="sbrc26-ataque-stp-tcn-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="net_ipv6_mld_flood",
            name="IPv6 MLD Flood",
            description="Flood MLD em rede local.",
            image_base="sbrc26-ataque-ipv6-mld-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="net_ipv6_ns_flood",
            name="IPv6 NS Flood",
            description="Flood de Neighbor Solicitation em rede local.",
            image_base="sbrc26-ataque-ipv6-ns-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
        A(
            id="net_ipv6_ra_flood",
            name="IPv6 RA Flood",
            description="Flood de Router Advertisements em rede local.",
            image_base="sbrc26-ataque-ipv6-ra-flood",
            params=[],
            no_params_note="Este ataque não recebe parâmetros e atua em nível de rede local.",
            details_warning=(
                "Este ataque pode gerar muitos dados se for capturado até seu término automático. "
                "Para fins de demonstração, sugere-se parar manualmente o ataque alguns segundos após iniciado."
            ),
        ),
    ],

    "7) Exfiltração": [
        A(
            id="exf_dns_tunneling",
            name="DNS Tunneling",
            description="Exfiltração via DNS tunneling.",
            image_base="sbrc26-ataque-dns-tunneling",
            params=[],
            no_params_note=(
                "Este ataque não recebe parâmetros. Serão utilizados os servidores DNS "
                "1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112 e 76.76.19.19."
            ),
        ),
        A(
            id="exf_icmp_tunnel",
            name="ICMP Tunnel",
            description="Túnel/exfiltração via ICMP.",
            image_base="sbrc26-ataque-icmp-tunnel",
            params=[
                ParamSpec("target_ip", "Endereço IP do Alvo", "ip", placeholder="__HOST_IP__"),
                ParamSpec("target_port", "Porta do alvo", "port", placeholder="2222", default=2222),
            ],
        ),
    ],
}
