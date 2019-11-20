from myiputils import *
from ipaddress import *
from random import randint


def complementode2(val, bits):
    """compute the 2's complement of int value val"""
    if (val & (1 << (bits - 1))) != 0: # if sign bit is set e.g., 8bit: 128-255
        val = val - (1 << bits)        # compute negative value
    return val

def create_header_ipv4(seg_len, src_addr, dest_addr, dscp=None, ecn=None, identification=None, flags=None, frag_offset=None, ttl=255, proto=None, verifica_checksum=False):
    version = 4 << 4
    ihl = 5
    vihl = version + ihl

    if dscp is None:
        dscp = 0 << 6
    if ecn is None:
        ecn = 0

    dscpecn = dscp + ecn
    total_length = complementode2(seg_len + 20, 16)

    if identification is None:
        identification = complementode2(randint(0, 2**16), 16)

    if flags is None:
        flag_rsv = 0
        flag_dtf = 0
        flag_mrf = 0
        flags = (flag_rsv << 15) | (flag_dtf << 14) | (flag_mrf << 13)

    if proto is None:
        proto = IPPROTO_TCP
        
    if frag_offset is None:
        frag_offset = 0

    flags |= frag_offset
    ttl = complementode2(ttl, 8)

    checksum = 0
    src_addr = str2addr(src_addr)
    dest_addr = str2addr(dest_addr)
    header = struct.pack('!bbhhhbbh', vihl, dscpecn, total_length,
                         identification, flags, ttl, proto, checksum) + src_addr + dest_addr
    if verifica_checksum:
        checksum = complementode2(calc_checksum(header[:4*ihl]), 16)
        header = struct.pack('!bbhhhbbh', vihl, dscpecn, total_length,
                             identification, flags, ttl, proto, checksum) + src_addr + dest_addr

    return header

class CamadaRede:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.version = 4
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.meu_endereco = None
        self.tabela = []

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            if ttl > 1:
                hdr = create_header_ipv4(len(payload), src_addr, dst_addr, dscp, ecn, identification, flags, frag_offset, (ttl-1), proto, verifica_checksum=True)
                datagrama = hdr + payload
                self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):

        dest_addr = ip_address(dest_addr)

        for t in self.tabela:
            network = t[0]
            if dest_addr in network:
                return str(t[1])

        return None

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = [(ip_network(t[0]), ip_address(t[1])) for t in tabela]
        self.tabela.sort(key=lambda tup: tup[0].prefixlen, reverse=True)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        header = create_header_ipv4(len(segmento), self.meu_endereco, dest_addr, verifica_checksum=True)
        self.enlace.enviar(header+segmento, next_hop)
