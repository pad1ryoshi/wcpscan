#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Laboratorio de Envenenamento de Cache Web

Emula um cache intermediario ingenuo na frente de um servidor de origem, em
dez cenarios de comportamento distintos. Serve para validar a metodologia de
cinco etapas e a ferramenta wcpscan sem tocar em nenhum alvo externo.

Artefato do Trabalho de Conclusao de Curso "Envenenamento de Cache Web:
explorando falhas no design e na implementacao de web cache em aplicacoes web
modernas" (IFPB, 2026).

Os cenarios se dividem em tres grupos:

  VULNERAVEIS (4)   a entrada nao indexada existe e e explorvel.
                    A ferramenta deve reportar.

  CONTROLES (4)     ha cache e ha entrada que influencia a resposta, mas nao
                    ha envenenamento. Cada controle reproduz um motivo
                    diferente: o cabecalho e indexado via Vary, o cache
                    rejeita a resposta de erro, o recurso nao e cacheavel, ou
                    a resposta varia naturalmente a cada requisicao.
                    A ferramenta NAO deve reportar.

  RECUSAS (2)       o cache ignora o parametro de cache-buster, de modo que o
                    isolamento dos testes nao pode ser comprovado.
                    A ferramenta deve recusar o alvo antes de sondar.

Os controles negativos sao a parte deliberada do desenho. Um laboratorio
composto apenas de cenarios vulneraveis mediria somente a sensibilidade do
metodo. Com os controles, mede-se tambem a especificidade, isto e, a
capacidade de nao acusar falha onde nao ha.

Uso:
    python lab.py                 # 127.0.0.1:8099
    python lab.py --porta 9000
    python lab.py --listar        # imprime a tabela de cenarios e sai

Dependencias: nenhuma. Apenas a biblioteca padrao do Python 3.9+.
"""

from __future__ import annotations

import argparse
import random
import string
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.parse import urlsplit

__version__ = "1.0"

LIMITE_CABECALHO = 4096          # limite de tamanho de cabecalho da "origem"
METACARACTERES = set(range(0, 32)) | {127}


# --------------------------------------------------------------------------
# Servidores de origem
# --------------------------------------------------------------------------


def corpo_legitimo(rota: str) -> bytes:
    return (
        "<html><head><title>%s</title></head>"
        "<body><h1>Conteudo legitimo</h1><p>Recurso: %s</p></body></html>"
        % (rota, rota)
    ).encode()


def origem_estatica(h, rota):
    """Origem que ignora todo cabecalho de entrada."""
    return 200, corpo_legitimo(rota)


def origem_reflete_host(h, rota):
    """Origem que reflete X-Forwarded-Host no atributo src de uma tag script.

    E o comportamento tipico de aplicacao que monta URLs absolutas a partir do
    cabecalho de encaminhamento informado pelo proxy.
    """
    host = h.get("x-forwarded-host")
    if not host:
        return 200, corpo_legitimo(rota)
    return 200, (
        '<html><head><script src="//%s/static/app.js"></script></head>'
        "<body><h1>Conteudo legitimo</h1></body></html>" % host
    ).encode()


def origem_sobrescrita_metodo(h, rota):
    """Origem que honra a sobrescrita de metodo HTTP.

    E o comportamento do cenario estudado no trabalho. O cabecalho existe por
    compatibilidade com clientes que nao emitem todos os metodos, e a origem o
    honra. Quando o metodo sobrescrito nao produz corpo, a resposta e um 200
    com corpo vazio.

    Esse artefato e o ponto central do cenario: nao e uma resposta de erro.
    Qualquer mitigacao ou deteccao baseada em codigo de status o deixa passar.
    """
    override = h.get("x-http-method-override") or h.get("x-method-override") \
        or h.get("x-http-method") or ""
    if override.strip().upper() in ("HEAD", "POST", "PUT", "DELETE", "OPTIONS"):
        return 200, b""
    return 200, corpo_legitimo(rota)


def origem_cabecalho_sobredimensionado(h, rota):
    """Origem que rejeita requisicao com cabecalho acima do limite.

    Variante HHO (HTTP Header Oversize) do CPDoS.
    """
    for valor in h.values():
        if len(valor) > LIMITE_CABECALHO:
            return 400, (
                b"<html><body><h1>400 Bad Request</h1>"
                b"<p>Request Header Too Large</p></body></html>"
            )
    return 200, corpo_legitimo(rota)


def origem_metacaractere(h, rota):
    """Origem que rejeita requisicao com metacaractere em cabecalho.

    Variante HMC (HTTP Meta Character) do CPDoS.
    """
    for valor in h.values():
        if any(ord(c) in METACARACTERES for c in valor):
            return 400, (
                b"<html><body><h1>400 Bad Request</h1>"
                b"<p>Malformed Request Header</p></body></html>"
            )
    return 200, corpo_legitimo(rota)


# --------------------------------------------------------------------------
# Cenarios
# --------------------------------------------------------------------------


@dataclass
class Cenario:
    rota: str
    grupo: str                   # vulneravel | controle | recusa
    trilha: str                  # integridade | disponibilidade | -
    descricao: str
    esperado: str

    origem: Callable = origem_estatica
    # comportamento do cache
    cacheavel: bool = True
    indexa_query: bool = True
    indexa_forwarded_host: bool = False
    armazena_erro: bool = True
    emite_estado: bool = False       # X-Cache: HIT / MISS
    emite_age: bool = True
    injeta_id: bool = False          # simula borda que injeta id por resposta
    ttl: int = 60


CENARIOS = [
    # ---------------- vulneraveis ----------------
    Cenario(
        rota="/vuln/unkeyed-header",
        grupo="vulneravel",
        trilha="integridade",
        descricao="X-Forwarded-Host nao indexado e refletido em <script src>",
        esperado="achado: reflexao do valor na resposta",
        origem=origem_reflete_host,
        emite_estado=True,
    ),
    Cenario(
        rota="/vuln/hmo",
        grupo="vulneravel",
        trilha="disponibilidade",
        descricao=("origem honra X-HTTP-Method-Override e devolve 200 com corpo "
                   "vazio; cache sem estado declarado, apenas Age"),
        esperado="achado: divergencia de corpo, sem reflexao",
        origem=origem_sobrescrita_metodo,
        emite_estado=False,
    ),
    Cenario(
        rota="/vuln/hho",
        grupo="vulneravel",
        trilha="disponibilidade",
        descricao="cabecalho sobredimensionado gera 400 e o cache armazena o erro",
        esperado="achado: divergencia de status 200 para 400",
        origem=origem_cabecalho_sobredimensionado,
        emite_estado=True,
    ),
    Cenario(
        rota="/vuln/hmc",
        grupo="vulneravel",
        trilha="disponibilidade",
        descricao=("metacaractere em cabecalho gera 400 e o cache armazena o "
                   "erro; cache sem estado e sem Age, so Cache-Control"),
        esperado="achado: divergencia de status 200 para 400",
        origem=origem_metacaractere,
        emite_estado=False,
        emite_age=False,
    ),

    # ---------------- controles negativos ----------------
    Cenario(
        rota="/controle/vary",
        grupo="controle",
        trilha="-",
        descricao=("X-Forwarded-Host influencia a resposta, porem o cache o "
                   "INDEXA via Vary, de modo que cada valor gera entrada propria"),
        esperado="sem achado: a divergencia existe, o armazenamento indevido nao",
        origem=origem_reflete_host,
        indexa_forwarded_host=True,
        emite_estado=True,
    ),
    Cenario(
        rota="/controle/erro-nao-armazenado",
        grupo="controle",
        trilha="-",
        descricao=("cabecalho sobredimensionado gera 400, mas o cache recusa "
                   "armazenar resposta de erro"),
        esperado="sem achado: o erro nao persiste na entrada de cache",
        origem=origem_cabecalho_sobredimensionado,
        armazena_erro=False,
        emite_estado=True,
    ),
    Cenario(
        rota="/controle/sem-cache",
        grupo="controle",
        trilha="-",
        descricao="recurso declarado no-store; nao ha cache intermediario atuando",
        esperado="sem cache confirmado na Etapa 1",
        origem=origem_reflete_host,
        cacheavel=False,
    ),
    Cenario(
        rota="/controle/dinamico",
        grupo="controle",
        trilha="-",
        descricao=("borda injeta um identificador de tamanho variavel em cada "
                   "resposta, de modo que o corpo nunca e identico"),
        esperado="sem achado: a variacao natural nao deve ser lida como divergencia",
        origem=origem_estatica,
        injeta_id=True,
        emite_estado=True,
    ),

    # ---------------- recusas de oraculo ----------------
    Cenario(
        rota="/recusa/query-ignorada",
        grupo="recusa",
        trilha="-",
        descricao=("o cache nao inclui a query string na chave, logo o "
                   "cache-buster nao isola o teste"),
        esperado="oraculo recusado: buster servido do cache",
        origem=origem_reflete_host,
        indexa_query=False,
        emite_age=True,
    ),
    Cenario(
        rota="/recusa/cache-mudo",
        grupo="recusa",
        trilha="-",
        descricao=("o cache ignora a query string e nao emite estado nem Age; "
                   "so o cabecalho Date denuncia o reaproveitamento"),
        esperado="oraculo recusado: Date identico apos a espera",
        origem=origem_reflete_host,
        indexa_query=False,
        emite_age=False,
    ),
]

POR_ROTA = {c.rota: c for c in CENARIOS}


# --------------------------------------------------------------------------
# O cache intermediario
# --------------------------------------------------------------------------


@dataclass
class Entrada:
    status: int
    corpo: bytes
    data: str
    nascimento: float


ARMAZEM: dict = {}


def chave_de_cache(cenario: Cenario, qs: str, cabecalhos) -> tuple:
    """Monta a chave de cache conforme o comportamento declarado do cenario.

    A chave e o coracao do laboratorio: e exatamente a divergencia entre o que
    entra nesta funcao e o que a origem efetivamente consome que determina se o
    cenario e vulneravel.
    """
    partes = [cenario.rota]
    partes.append(qs if cenario.indexa_query else "")
    partes.append(
        cabecalhos.get("x-forwarded-host", "") if cenario.indexa_forwarded_host else ""
    )
    return tuple(partes)


def identificador() -> bytes:
    n = random.randint(8, 24)
    marca = "".join(random.choice(string.hexdigits.lower()) for _ in range(n))
    return ("\n<!-- edge-request-id: %s -->" % marca).encode()


class Manipulador(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "lab-wcp/%s" % __version__

    def log_message(self, formato, *args):
        if self.server.verboso:
            super().log_message(formato, *args)

    # -- utilidades --------------------------------------------------------

    def responder(self, status, corpo, extra=None, data=None):
        # Um cache real repassa ao cliente a Date gerada pela origem quando
        # serve a resposta do proprio armazenamento. Reproduzir isso importa,
        # porque a Date e o terceiro sinal usado para decidir se o
        # cache-buster integra a chave.
        self.send_response_only(status)
        self.send_header("Server", self.server_version)
        self.send_header("Date", data or self.date_time_string())
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        for nome, valor in (extra or {}).items():
            self.send_header(nome, valor)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(corpo)

    def indice(self):
        linhas = [
            "<html><head><title>Laboratorio de Envenenamento de Cache Web</title>",
            "<style>body{font-family:sans-serif;max-width:60em;margin:2em auto}"
            "td,th{padding:.3em .6em;border-bottom:1px solid #ddd;text-align:left}"
            "code{background:#f4f4f4;padding:.1em .3em}</style></head><body>",
            "<h1>Laboratorio de Envenenamento de Cache Web</h1>",
            "<p>Artefato do TCC. Dez cenarios de comportamento de cache.</p>",
            "<table><tr><th>Rota</th><th>Grupo</th><th>Trilha</th>"
            "<th>Resultado esperado</th></tr>",
        ]
        for c in CENARIOS:
            linhas.append(
                "<tr><td><a href='%s'><code>%s</code></a></td><td>%s</td>"
                "<td>%s</td><td>%s</td></tr>"
                % (c.rota, c.rota, c.grupo, c.trilha, c.esperado)
            )
        linhas.append("</table></body></html>")
        corpo = "".join(linhas).encode()
        return self.responder(200, corpo, {"Cache-Control": "no-store"})

    # -- metodos HTTP ------------------------------------------------------

    def do_HEAD(self):
        self.servir()

    def do_POST(self):
        self.servir()

    def do_GET(self):
        self.servir()

    def servir(self):
        partes = urlsplit(self.path)
        rota, qs = partes.path, partes.query
        cabecalhos = {k.lower(): v for k, v in self.headers.items()}

        if rota in ("/", "/index.html"):
            return self.indice()

        cenario = POR_ROTA.get(rota.rstrip("/")) or POR_ROTA.get(rota)
        if cenario is None:
            return self.responder(
                404, b"<html><body><h1>404</h1></body></html>",
                {"Cache-Control": "no-store"}
            )

        # Recurso nao cacheavel: a origem responde sempre.
        if not cenario.cacheavel:
            status, corpo = cenario.origem(cabecalhos, cenario.rota)
            return self.responder(status, corpo, {"Cache-Control": "no-store"})

        chave = chave_de_cache(cenario, qs, cabecalhos)
        agora = time.time()
        guardada = ARMAZEM.get(chave)

        # --- acerto de cache ---
        if guardada and agora - guardada.nascimento < cenario.ttl:
            corpo = guardada.corpo
            if cenario.injeta_id:
                corpo = corpo + identificador()
            extra = {"Cache-Control": "public, max-age=%d" % cenario.ttl}
            if cenario.emite_age:
                extra["Age"] = str(int(agora - guardada.nascimento))
            if cenario.emite_estado:
                extra["X-Cache"] = "HIT"
            return self.responder(guardada.status, corpo, extra,
                                  data=guardada.data)

        # --- erro de cache: consulta a origem ---
        status, corpo = cenario.origem(cabecalhos, cenario.rota)
        data = self.date_time_string()

        armazenar = status < 400 or cenario.armazena_erro
        if armazenar:
            ARMAZEM[chave] = Entrada(status=status, corpo=corpo,
                                     data=data, nascimento=agora)

        enviado = corpo + identificador() if cenario.injeta_id else corpo
        extra = {"Cache-Control": "public, max-age=%d" % cenario.ttl}
        if cenario.emite_age:
            extra["Age"] = "0"
        if cenario.emite_estado:
            extra["X-Cache"] = "MISS" if armazenar else "BYPASS"
        return self.responder(status, enviado, extra, data=data)


class Servidor(ThreadingHTTPServer):
    allow_reuse_address = False
    verboso = False


# --------------------------------------------------------------------------


def tabela_de_cenarios() -> str:
    largura = max(len(c.rota) for c in CENARIOS)
    linhas = ["%-*s  %-11s  %-15s  %s" % (largura, "ROTA", "GRUPO", "TRILHA",
                                          "RESULTADO ESPERADO"),
              "-" * (largura + 60)]
    for grupo in ("vulneravel", "controle", "recusa"):
        for c in CENARIOS:
            if c.grupo == grupo:
                linhas.append("%-*s  %-11s  %-15s  %s"
                              % (largura, c.rota, c.grupo, c.trilha, c.esperado))
        linhas.append("")
    return "\n".join(linhas)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="lab",
        description="Laboratorio de Envenenamento de Cache Web (artefato de TCC).",
    )
    ap.add_argument("--porta", type=int, default=8099)
    ap.add_argument("--endereco", default="127.0.0.1",
                    help="padrao 127.0.0.1; o laboratorio e deliberadamente "
                         "vulneravel e nao deve ser exposto na rede")
    ap.add_argument("--listar", action="store_true",
                    help="imprime a tabela de cenarios e sai")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.listar:
        print(tabela_de_cenarios())
        return 0

    servidor = Servidor((args.endereco, args.porta), Manipulador)
    servidor.verboso = args.verbose
    print("laboratorio em http://%s:%d" % (args.endereco, args.porta), flush=True)
    print("%d cenarios: %d vulneraveis, %d controles, %d recusas"
          % (len(CENARIOS),
             sum(1 for c in CENARIOS if c.grupo == "vulneravel"),
             sum(1 for c in CENARIOS if c.grupo == "controle"),
             sum(1 for c in CENARIOS if c.grupo == "recusa")), flush=True)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\nencerrado", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
