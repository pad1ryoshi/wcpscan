#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wcpscan — triagem automatizada de Envenenamento de Cache Web (Web Cache Poisoning)

Ferramenta desenvolvida como artefato do Trabalho de Conclusao de Curso
"Envenenamento de Cache Web: explorando falhas no design e na implementacao de
web cache em aplicacoes web modernas" (IFPB, 2026).

A ferramenta automatiza as Etapas 1 a 3 da metodologia proposta no trabalho:

    Etapa 1  identificar se existe cache na aplicacao web
    Etapa 2  identificar um oraculo, isto e, uma requisicao especifica
             sobre a qual o cache pode ser manipulado com seguranca
    Etapa 3  verificar se existem entradas nao indexadas (unkeyed inputs)
             que influenciam a resposta

As Etapas 4 e 5 (exploracao e confirmacao da exploracao) permanecem manuais,
por exigirem julgamento sobre o contexto e sobre o impacto do achado.

GARANTIA ETICA
    Toda requisicao enviada pela ferramenta carrega um cache-buster unico.
    Nao existe opcao de desligar esse comportamento. Em consequencia, qualquer
    resposta divergente induzida durante a triagem fica presa a uma chave de
    cache que nenhum usuario legitimo da aplicacao solicita. A fase de
    confirmacao verifica explicitamente esse isolamento antes de reportar.

    A ferramenta nao executa payloads de exploracao, nao persiste conteudo
    malicioso e nao tenta envenenar a chave de cache real do recurso.

Dependencias: nenhuma. Apenas a biblioteca padrao do Python 3.9+.

Uso:
    python wcpscan.py -l hosts.txt -o resultado.json
    python wcpscan.py -u https://alvo.example/static/app.js --rate 2
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import random
import re
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict

__version__ = "1.0"

# --------------------------------------------------------------------------
# Constantes
# --------------------------------------------------------------------------

# Cabecalhos que declaram explicitamente o estado da entrada de cache.
# A presenca de um valor de acerto (hit) nesses cabecalhos e evidencia direta
# de que a resposta foi servida por um cache intermediario.
CABECALHOS_ESTADO_CACHE = (
    "x-cache",
    "x-cache-status",
    "x-cache-hits",
    "cf-cache-status",
    "x-proxy-cache",
    "x-varnish-cache",
    "x-drupal-cache",
    "x-vercel-cache",
    "x-nextjs-cache",
    "cdn-cache",
    "x-litespeed-cache",
    "x-rack-cache",
    "x-fastcgi-cache",
)

# Cabecalhos que apenas revelam a presenca de um intermediario na cadeia,
# sem informar o estado da entrada. Sozinhos nao confirmam cache.
CABECALHOS_INTERMEDIARIO = (
    "via",
    "x-served-by",
    "x-timer",
    "x-amz-cf-id",
    "x-amz-cf-pop",
    "x-akamai-request-id",
    "x-edge-location",
    "server-timing",
)

# Assinaturas de origem e de borda, uteis para caracterizar o alvo no relato
# do estudo de caso. A assinatura do Google Cloud Storage e relevante porque
# o cache interno do GCS nao emite cabecalho de estado ao cliente: nesse
# cenario a deteccao depende exclusivamente da inferencia pelo Age.
ASSINATURAS_ORIGEM = (
    ("Google Cloud Storage", ("x-goog-generation", "x-goog-hash", "x-guploader-uploadid")),
    ("Google Cloud (borda)", ("via: 1.1 google",)),
    ("Amazon S3", ("x-amz-request-id", "x-amz-id-2")),
    ("Amazon CloudFront", ("x-amz-cf-id",)),
    ("Cloudflare", ("cf-ray", "cf-cache-status")),
    ("Fastly", ("x-served-by", "x-timer")),
    ("Akamai", ("x-akamai-request-id", "akamai-grn")),
    ("Varnish", ("x-varnish",)),
    ("Nginx", ("x-nginx-cache",)),
)

# Caminhos sondados quando a entrada e apenas um host, sem caminho explicito.
# A lista privilegia recursos que costumam ser cacheaveis por padrao.
CAMINHOS_PADRAO = (
    "/",
    "/robots.txt",
    "/favicon.ico",
    "/static/",
    "/assets/",
    "/index.html",
)

# Valor neutro usado nas sondas de sobrescrita de metodo. GET e HEAD sao
# metodos seguros: o objetivo e observar divergencia de resposta, nunca
# provocar efeito colateral no servidor de origem.
METODOS_SONDA = ("HEAD", "POST")

UA_PADRAO = (
    "wcpscan/%s (pesquisa academica de seguranca; TCC IFPB 2026)" % __version__
)


# --------------------------------------------------------------------------
# Infraestrutura de rede
# --------------------------------------------------------------------------


class LimitadorDeTaxa:
    """Limitador de requisicoes por segundo aplicado POR HOST.

    O controle de taxa e um mecanismo etico, nao apenas operacional: evita que
    a triagem automatizada gere trafego capaz de degradar o alvo. A garantia,
    porem, e por alvo -- o que precisa ser evitado e sobrecarregar uma
    aplicacao especifica em producao. Hosts distintos nao competem entre si,
    de modo que a vazao total cresce com o numero de alvos examinados em
    paralelo sem afrouxar o limite imposto a cada um deles.

    O teto global permanece disponivel como salvaguarda opcional, util quando
    varios alvos compartilham a mesma infraestrutura de origem ou quando a
    banda do ponto de partida e limitada.
    """

    def __init__(self, por_segundo: float, teto_global: float = 0.0):
        self._intervalo = 1.0 / por_segundo if por_segundo > 0 else 0.0
        self._intervalo_global = 1.0 / teto_global if teto_global > 0 else 0.0
        self._proximo = {}
        self._proximo_global = 0.0
        self._trava = threading.Lock()

    def aguardar(self, host: str = "") -> None:
        if self._intervalo <= 0 and self._intervalo_global <= 0:
            return
        # A trava e liberada antes do sleep: segura-la durante a espera
        # serializaria as threads e anularia o ganho do limite por host.
        with self._trava:
            agora = time.monotonic()
            espera = 0.0
            if self._intervalo > 0:
                proximo = self._proximo.get(host, 0.0)
                if proximo < agora:
                    proximo = agora
                espera = proximo - agora
                self._proximo[host] = proximo + self._intervalo
            if self._intervalo_global > 0:
                if self._proximo_global < agora:
                    self._proximo_global = agora
                espera = max(espera, self._proximo_global - agora)
                self._proximo_global += self._intervalo_global
        if espera > 0:
            time.sleep(espera)


@dataclass
class Resposta:
    status: int
    cabecalhos: dict
    corpo: bytes
    decorrido: float
    erro: str = ""
    # Corpo maior que o limite de leitura: dois corpos distintos truncados no
    # mesmo ponto comparariam iguais, o que o chamador precisa saber.
    truncado: bool = False

    @property
    def digest(self) -> str:
        return hashlib.sha1(self.corpo).hexdigest()

    @property
    def tamanho(self) -> int:
        return len(self.corpo)

    def cabecalho(self, nome: str) -> str:
        return self.cabecalhos.get(nome.lower(), "")

    def idade(self):
        bruto = self.cabecalho("age").strip()
        if bruto.isdigit():
            return int(bruto)
        return None


class Cliente:
    """Cliente HTTP sobre http.client, com conexao persistente por host.

    Cada thread guarda suas proprias conexoes, de modo que nao ha
    compartilhamento entre threads nem necessidade de sincronizacao.
    Reaproveitar a conexao elimina o handshake TCP e TLS de cada requisicao,
    que era o maior custo isolado da triagem: medido contra o laboratorio,
    sem limite de taxa, a diferenca foi de 90 para 2116 requisicoes por
    segundo, e contra um host HTTPS remoto a diferenca e maior, porque cada
    requisicao pagava tambem o handshake TLS.

    O redirecionamento nao e seguido, porque http.client nao o segue: um 301
    ou 302 e ele proprio um sinal de divergencia relevante para a Etapa 3.

    Alem do cache por thread, cada conexao aberta e registrada numa lista
    compartilhada. A Etapa 3 cria um pool de threads proprio por alvo (ver
    sondar_entradas), de modo que as conexoes de um alvo ficam espalhadas por
    threads que deixam de existir quando aquele pool termina: nenhuma thread
    futura tem como alcanca-las pelo cache local para fecha-las a tempo. Sem
    fechamento explicito, essas conexoes so morrem quando o processo termina,
    e o Windows fecha os sockets de modo abrupto nesse instante -- o servidor,
    ainda bloqueado esperando a proxima requisicao naquela conexao
    persistente, recebe isso como ConnectionResetError. fechar_tudo() resolve
    isso de uma vez, a partir da thread principal, depois que todo o trabalho
    concorrente (o pool de alvos e os pools de sondagem de cada alvo) ja
    terminou -- ponto em que fechar um socket de outra thread e seguro, por
    nao haver mais ninguem usando-o.
    """

    def __init__(self, limitador, timeout=12.0, verificar_tls=True,
                 user_agent=UA_PADRAO, limite_corpo=512 * 1024):
        self.limitador = limitador
        self.timeout = timeout
        self.user_agent = user_agent
        self.limite_corpo = limite_corpo

        self._contexto = ssl.create_default_context()
        if not verificar_tls:
            self._contexto.check_hostname = False
            self._contexto.verify_mode = ssl.CERT_NONE

        self._local = threading.local()
        self._todas = []
        self._trava_todas = threading.Lock()

    # -- gerencia das conexoes ------------------------------------------

    def _cache(self) -> dict:
        if not hasattr(self._local, "conexoes"):
            self._local.conexoes = {}
        return self._local.conexoes

    def _abrir(self, chave):
        esquema, host, porta = chave
        if esquema == "https":
            conexao = http.client.HTTPSConnection(
                host, porta, timeout=self.timeout, context=self._contexto)
        else:
            conexao = http.client.HTTPConnection(host, porta, timeout=self.timeout)
        with self._trava_todas:
            self._todas.append(conexao)
        return conexao

    def _descartar(self, chave) -> None:
        conexao = self._cache().pop(chave, None)
        if conexao is not None:
            try:
                conexao.close()
            except Exception:
                pass

    def fechar(self) -> None:
        """Encerra as conexoes abertas pela thread corrente."""
        for chave in list(self._cache()):
            self._descartar(chave)

    def fechar_tudo(self) -> None:
        """Encerra TODAS as conexoes, de qualquer thread.

        So e seguro depois que todo o trabalho concorrente terminou: fechar o
        socket de uma thread que ainda pode usa-lo causaria erro nela.
        """
        with self._trava_todas:
            pendentes, self._todas = self._todas, []
        for conexao in pendentes:
            try:
                conexao.close()
            except Exception:
                pass

    # -- requisicao ------------------------------------------------------

    def buscar(self, url: str, cabecalhos=None, metodo="GET") -> Resposta:
        partes = urllib.parse.urlsplit(url)
        esquema = (partes.scheme or "http").lower()
        host = partes.hostname or ""
        porta = partes.port or (443 if esquema == "https" else 80)
        caminho = partes.path or "/"
        if partes.query:
            caminho += "?" + partes.query
        chave = (esquema, host, porta)

        self.limitador.aguardar(partes.netloc.lower())

        enviar = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            # Sem compressao, para que o tamanho do corpo seja diretamente
            # comparavel entre a referencia e as sondas.
            "Accept-Encoding": "identity",
        }
        enviar.update(cabecalhos or {})

        inicio = time.monotonic()
        cache = self._cache()
        for tentativa in (0, 1):
            reaproveitada = chave in cache
            conexao = cache.get(chave)
            if conexao is None:
                conexao = self._abrir(chave)
                cache[chave] = conexao
            try:
                conexao.request(metodo, caminho, headers=enviar)
                resposta = conexao.getresponse()
                # Le um byte alem do limite para saber se houve truncamento.
                corpo = resposta.read(self.limite_corpo + 1)
                truncado = len(corpo) > self.limite_corpo
                if truncado:
                    corpo = corpo[:self.limite_corpo]
                cabs = {k.lower(): v for k, v in resposta.getheaders()}
                # Uma conexao com corpo por ler nao pode ser reaproveitada.
                if truncado or resposta.will_close or                         cabs.get("connection", "").lower() == "close":
                    self._descartar(chave)
                return Resposta(
                    status=resposta.status,
                    cabecalhos=cabs,
                    corpo=corpo,
                    decorrido=time.monotonic() - inicio,
                    truncado=truncado,
                )
            except Exception as exc:
                self._descartar(chave)
                # Conexao ociosa encerrada pelo servidor e indistinguivel de
                # falha real na primeira tentativa. Repetir so faz sentido
                # quando a conexao vinha do cache; uma conexao recem-aberta
                # que falha indica alvo inacessivel, e insistir dobraria o
                # custo de cada host morto.
                if tentativa == 0 and reaproveitada:
                    continue
                return Resposta(
                    status=0,
                    cabecalhos={},
                    corpo=b"",
                    decorrido=time.monotonic() - inicio,
                    erro="%s: %s" % (type(exc).__name__, exc),
                )


# --------------------------------------------------------------------------
# Cache-buster
# --------------------------------------------------------------------------


def token(n: int = 10) -> str:
    alfabeto = string.ascii_lowercase + string.digits
    return "".join(random.choice(alfabeto) for _ in range(n))


def aplicar_buster(url: str, valor: str, parametro: str = "cb") -> str:
    """Acrescenta o parametro de cache-buster a URL, preservando a query."""
    partes = urllib.parse.urlsplit(url)
    consulta = urllib.parse.parse_qsl(partes.query, keep_blank_values=True)
    consulta = [(c, v) for c, v in consulta if c != parametro]
    consulta.append((parametro, valor))
    return urllib.parse.urlunsplit(
        (partes.scheme, partes.netloc, partes.path or "/",
         urllib.parse.urlencode(consulta), "")
    )


# --------------------------------------------------------------------------
# Sondas de entrada nao indexada
# --------------------------------------------------------------------------


@dataclass
class Sonda:
    """Uma sonda e um cabecalho candidato a entrada nao indexada.

    O campo `classe` distingue a trilha de exploracao que a sonda investiga:

        integridade    o atacante controla o conteudo servido a terceiros
        disponibilidade o atacante torna o recurso inutilizavel para terceiros

    A separacao importa porque a trilha de disponibilidade nao depende de
    reflexao do valor na resposta. No caso de sobrescrita de metodo HTTP, por
    exemplo, o artefato armazenado pode ser uma resposta de status 200 com
    corpo vazio, que nenhum criterio baseado em reflexao ou em codigo de erro
    conseguiria detectar.
    """

    nome: str
    valor: str
    classe: str
    tipo: str  # canario | metodo | sobredimensionado | metacaractere


def montar_sondas(cabecalhos_canario, canario: str, habilitar_dos=True):
    sondas = []

    # Trilha de integridade: cabecalhos de encaminhamento e de reescrita de
    # URL, cujo valor tende a ser refletido ou a redirecionar a aplicacao.
    for nome in cabecalhos_canario:
        nome = nome.strip()
        if not nome or nome.startswith("#"):
            continue
        baixo = nome.lower()
        if "url" in baixo or "path" in baixo or "prefix" in baixo:
            valor = "/%s" % canario
        elif "port" in baixo:
            valor = "1337"
        elif "scheme" in baixo or "proto" in baixo:
            valor = "http"
        else:
            valor = "%s.example" % canario
        sondas.append(Sonda(nome, valor, "integridade", "canario"))

    if not habilitar_dos:
        return sondas

    # Trilha de disponibilidade, variante HMO (HTTP Method Override).
    # O sinal esperado nao e reflexao, e divergencia de corpo ou de status
    # em relacao a resposta de referencia.
    for cabecalho in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"):
        for metodo in METODOS_SONDA:
            sondas.append(
                Sonda(cabecalho, metodo, "disponibilidade", "metodo")
            )

    # Variante HHO (HTTP Header Oversize). O cabecalho e grande o bastante
    # para ultrapassar o limite de servidores de origem comuns, mas nao a
    # ponto de caracterizar abuso de recurso.
    sondas.append(
        Sonda("X-Oversized-Header", "A" * 8192, "disponibilidade", "sobredimensionado")
    )

    # Variante HMC (HTTP Meta Character).
    sondas.append(
        Sonda("X-Metachar-Header", "\x00", "disponibilidade", "metacaractere")
    )

    return sondas


# --------------------------------------------------------------------------
# Fase 1 — existe cache?
# --------------------------------------------------------------------------


@dataclass
class Alvo:
    url: str
    tem_cache: bool = False
    evidencia: str = ""
    metodo_deteccao: str = ""
    origem: str = ""
    status: int = 0
    cache_control: str = ""
    ttl_declarado: int = -1
    erro: str = ""


def identificar_origem(resp: Resposta) -> str:
    achatado = " ".join(
        "%s: %s" % (k, v) for k, v in sorted(resp.cabecalhos.items())
    ).lower()
    encontrados = []
    for rotulo, marcas in ASSINATURAS_ORIGEM:
        for marca in marcas:
            if marca in achatado:
                encontrados.append(rotulo)
                break
    return ", ".join(encontrados)


def sinal_de_acerto(resp: Resposta):
    """Classifica a resposta como acerto, erro de cache ou indeterminada.

    Retorna True para acerto, False para erro de cache e None quando a
    resposta nao permite decidir. O caso indeterminado e frequente e precisa
    ser tratado como tal: `Age: 0` tanto pode ser um erro de cache quanto um
    acerto sobre uma entrada armazenada ha menos de um segundo.
    """
    for nome in CABECALHOS_ESTADO_CACHE:
        valor = resp.cabecalho(nome)
        if not valor:
            continue
        if re.search(r"\bhit\b", valor, re.I):
            return True
        if re.search(r"\b(miss|expired|dynamic|bypass|none|pass|stale)\b", valor, re.I):
            return False
    idade = resp.idade()
    if idade is not None and idade > 0:
        return True
    return None


def ttl_de(resp: Resposta) -> int:
    cc = resp.cabecalho("cache-control").lower()
    achado = re.search(r"s-maxage\s*=\s*(\d+)", cc) or re.search(r"max-age\s*=\s*(\d+)", cc)
    return int(achado.group(1)) if achado else -1


def detectar_cache(cliente: Cliente, url: str) -> Alvo:
    """Etapa 1 da metodologia: confirmar a existencia de cache intermediario.

    Sao usadas tres trilhas de deteccao, em ordem decrescente de certeza:

      1. cabecalho de estado declarando acerto (X-Cache: HIT e equivalentes)
      2. cabecalho Age, presente ou crescente entre duas requisicoes
      3. inferencia por corpo identico, diretiva publica de armazenamento e
         queda de latencia entre a primeira e a segunda requisicao

    A segunda trilha e indispensavel. Provedores relevantes nao expoem estado
    de cache ao cliente, e uma metodologia que dependesse apenas de X-Cache
    deixaria de detectar justamente esses alvos.
    """
    alvo = Alvo(url=url)
    buster = token()
    alvejada = aplicar_buster(url, buster)

    primeira = cliente.buscar(alvejada)
    if primeira.erro:
        alvo.erro = primeira.erro
        return alvo

    segunda = cliente.buscar(alvejada)
    if segunda.erro:
        alvo.erro = segunda.erro
        return alvo

    alvo.status = segunda.status
    alvo.origem = identificar_origem(segunda)
    alvo.cache_control = segunda.cabecalho("cache-control")
    alvo.ttl_declarado = ttl_de(segunda)

    # Trilha 1 — estado declarado.
    for nome in CABECALHOS_ESTADO_CACHE:
        valor = segunda.cabecalho(nome)
        if valor and re.search(r"\bhit\b", valor, re.I):
            alvo.tem_cache = True
            alvo.metodo_deteccao = "estado declarado"
            alvo.evidencia = "%s: %s" % (nome, valor)
            return alvo

    # Trilha 2 — Age positivo ou crescente.
    # `Age: 0` nas duas respostas nao e evidencia: origens que nunca servem do
    # cache tambem emitem o cabecalho zerado. So um valor positivo, ou o
    # incremento entre as duas requisicoes, comprova que ha entrada armazenada.
    idade_1, idade_2 = primeira.idade(), segunda.idade()
    if idade_2 is not None and idade_2 > 0:
        alvo.tem_cache = True
        alvo.metodo_deteccao = "inferencia por Age"
        alvo.evidencia = "Age: %d na segunda requisicao" % idade_2
        return alvo
    if idade_1 is not None and idade_2 is not None and idade_2 > idade_1:
        alvo.tem_cache = True
        alvo.metodo_deteccao = "inferencia por Age"
        alvo.evidencia = "Age crescente entre as duas respostas (%d para %d)" % (
            idade_1, idade_2)
        return alvo

    # Trilha 3 — inferencia por armazenabilidade declarada e latencia.
    cc = alvo.cache_control.lower()
    armazenavel = (
        alvo.ttl_declarado > 0
        and "no-store" not in cc
        and "private" not in cc
    )
    corpo_estavel = primeira.digest == segunda.digest and primeira.status == segunda.status
    acelerou = segunda.decorrido < primeira.decorrido * 0.6
    if armazenavel and corpo_estavel:
        alvo.tem_cache = True
        alvo.metodo_deteccao = "inferencia por armazenabilidade"
        alvo.evidencia = "Cache-Control: %s, corpo estavel%s" % (
            alvo.cache_control, ", latencia menor na 2a requisicao" if acelerou else ""
        )
        return alvo

    # Nenhuma trilha confirmou armazenamento. Registrar o que *foi* observado e
    # tao importante quanto o veredito: numa lista extensa, sem essa informacao
    # nao ha como distinguir um conjunto de alvos sem cache de uma falha de
    # deteccao, e todos os alvos descartados viram uma linha so, identica.
    razoes = []
    for nome in CABECALHOS_ESTADO_CACHE:
        valor = segunda.cabecalho(nome)
        if valor:
            razoes.append("%s: %s" % (nome, valor.strip()))
            break
    if not razoes:
        if not alvo.cache_control:
            razoes.append("sem Cache-Control e sem cabecalho de estado")
        elif "no-store" in cc:
            razoes.append("Cache-Control: no-store")
        elif "private" in cc:
            razoes.append("Cache-Control: private")
        elif alvo.ttl_declarado <= 0:
            razoes.append("Cache-Control sem diretiva de frescor (%s)" % alvo.cache_control)
        elif not corpo_estavel:
            razoes.append("corpo ou status instavel entre as duas requisicoes")
    presentes = [h for h in CABECALHOS_INTERMEDIARIO if segunda.cabecalho(h)]
    if presentes:
        razoes.append("intermediario presente (%s)" % ", ".join(presentes))
    alvo.evidencia = ", ".join(razoes)

    return alvo


# --------------------------------------------------------------------------
# Fase 2 — escolher o oraculo
# --------------------------------------------------------------------------


@dataclass
class Oraculo:
    url: str
    parametro_buster: str
    referencia_digest: str
    referencia_status: int
    referencia_tamanho: int
    pagina_dinamica: bool
    tolerancia: int
    ttl_declarado: int
    origem: str
    evidencia_cache: str


def estabelecer_oraculo(cliente: Cliente, alvo: Alvo, parametro="cb"):
    """Etapa 2 da metodologia: validar o cache-buster e fixar a referencia.

    A validacao e dupla, conforme a metodologia: duas requisicoes com o mesmo
    valor de buster devem convergir para a mesma resposta, e uma requisicao
    com valor distinto deve produzir uma entrada nova. Se o parametro de
    consulta nao integrar a chave de cache, o isolamento nao esta garantido e
    o alvo e descartado da triagem automatizada, por nao ser possivel testa-lo
    sem risco de afetar usuarios reais.

    A requisicao de controle, com valor distinto, e enviada apenas depois de
    decorrido mais de um segundo do armazenamento da referencia. A espera e
    necessaria porque o cabecalho Age tem granularidade de um segundo: sem
    ela, um acerto sobre a entrada da referencia responderia `Age: 0` e seria
    confundido com um erro de cache, e o alvo seria sondado sem isolamento.

    Quando nem o estado declarado nem o Age permitem decidir, recorre-se ao
    cabecalho Date. Um cache que reutiliza a entrada repassa a data gerada
    pela origem, de modo que uma data identica apos mais de um segundo indica
    reaproveitamento. Se nenhum dos tres sinais estiver disponivel, o alvo e
    descartado: sem como comprovar o isolamento, nao ha como sondar a
    aplicacao sem risco de afetar usuarios reais.

    A funcao tambem caracteriza a estabilidade da resposta. Paginas com
    conteudo dinamico produzem corpos diferentes a cada requisicao, e nesse
    caso a comparacao por digest geraria falsos positivos em serie. Para elas
    a comparacao passa a ser por tamanho, com tolerancia derivada da propria
    variacao observada.
    """
    buster = token()
    url = aplicar_buster(alvo.url, buster, parametro)

    a = cliente.buscar(url)
    if a.erro:
        return None, "falha na requisicao de referencia: %s" % a.erro
    armazenado_em = time.monotonic()
    b = cliente.buscar(url)
    if b.erro:
        return None, "falha na segunda requisicao de referencia: %s" % b.erro

    # A referencia precisa estar efetivamente armazenada. Um erro de cache
    # declarado na segunda requisicao significa que o recurso deixa de ser
    # cacheavel quando o cache-buster e aplicado.
    if sinal_de_acerto(b) is False:
        return None, ("recurso nao e armazenado quando o cache-buster '%s' "
                      "e aplicado" % parametro)

    # Valor distinto precisa produzir entrada distinta. Se o cache servir a
    # resposta anterior para um buster novo, o parametro nao e indexado.
    espera = 1.3 - (time.monotonic() - armazenado_em)
    if espera > 0:
        time.sleep(espera)

    outro = cliente.buscar(aplicar_buster(alvo.url, token(), parametro))
    if outro.erro:
        return None, "falha na requisicao de controle: %s" % outro.erro

    reutilizou = sinal_de_acerto(outro)
    if reutilizou is True:
        return None, ("parametro '%s' nao integra a chave de cache "
                      "(buster novo foi servido do cache)" % parametro)
    if reutilizou is None:
        data_ref, data_ctl = a.cabecalho("date"), outro.cabecalho("date")
        if not data_ref or not data_ctl:
            return None, ("isolamento nao verificavel: o alvo nao expoe estado "
                          "de cache, Age nem Date")
        if data_ref == data_ctl:
            return None, ("parametro '%s' nao integra a chave de cache "
                          "(Date identico apos 1,3 s)" % parametro)

    dinamica = a.digest != b.digest
    tolerancia = max(abs(a.tamanho - b.tamanho) * 3, 64) if dinamica else 0

    return (
        Oraculo(
            url=alvo.url,
            parametro_buster=parametro,
            referencia_digest=b.digest,
            referencia_status=b.status,
            referencia_tamanho=b.tamanho,
            pagina_dinamica=dinamica,
            tolerancia=tolerancia,
            ttl_declarado=alvo.ttl_declarado,
            origem=alvo.origem,
            evidencia_cache=alvo.evidencia,
        ),
        "",
    )


# --------------------------------------------------------------------------
# Fase 3 — entradas nao indexadas
# --------------------------------------------------------------------------


@dataclass
class Achado:
    url: str
    cabecalho: str
    valor: str
    classe: str
    tipo: str
    sinal: str
    status_referencia: int
    status_sonda: int
    tamanho_referencia: int
    tamanho_sonda: int
    refletido: bool
    armazenado: bool = False
    isolado: bool = False
    observacao: str = ""


def houve_divergencia(oraculo: Oraculo, sonda_resp: Resposta, canario: str):
    """Compara a resposta da sonda com a referencia e classifica o sinal.

    O criterio e disjuntivo de proposito. Basta um dos sinais para que a
    entrada seja marcada como candidata:

        reflexao   o valor enviado aparece na resposta
        status     o codigo de status divergiu da referencia
        corpo      o corpo divergiu da referencia

    Um criterio conjuntivo, que exigisse reflexao, excluiria da triagem toda a
    trilha de disponibilidade, inclusive o caso em que a resposta armazenada e
    um 200 com corpo vazio.
    """
    corpo_texto = sonda_resp.corpo.decode("utf-8", "replace")
    refletido = canario in corpo_texto or any(
        canario in v for v in sonda_resp.cabecalhos.values()
    )
    if refletido:
        return "reflexao do valor na resposta", True

    if sonda_resp.status != oraculo.referencia_status:
        return (
            "divergencia de status (%d para %d)"
            % (oraculo.referencia_status, sonda_resp.status),
            False,
        )

    if oraculo.pagina_dinamica:
        delta = abs(sonda_resp.tamanho - oraculo.referencia_tamanho)
        if delta > oraculo.tolerancia:
            return (
                "divergencia de tamanho em pagina dinamica (%d bytes, tolerancia %d)"
                % (delta, oraculo.tolerancia),
                False,
            )
    else:
        if sonda_resp.digest != oraculo.referencia_digest:
            return (
                "divergencia de corpo (%d para %d bytes)"
                % (oraculo.referencia_tamanho, sonda_resp.tamanho),
                False,
            )

    return "", False


def confirmar_armazenamento(cliente: Cliente, oraculo: Oraculo, url_envenenada: str,
                            sonda_resp: Resposta) -> tuple:
    """Verifica se a resposta divergente foi efetivamente armazenada.

    Reenvia a mesma URL, com o mesmo cache-buster, porem SEM a sonda. Se a
    resposta divergente retornar, o cache a armazenou sob uma chave que nao
    inclui o cabecalho manipulado, o que caracteriza a entrada como nao
    indexada e o envenenamento como efetivo.

    Em seguida verifica o isolamento: uma requisicao com um cache-buster novo
    deve retornar a resposta legitima. Isso comprova que o envenenamento ficou
    restrito a chave de teste e que nenhum usuario real foi afetado, que e a
    condicao etica para reportar o achado.
    """
    eco = cliente.buscar(url_envenenada)
    if eco.erro:
        return False, False, "falha na verificacao de armazenamento: %s" % eco.erro

    if oraculo.pagina_dinamica:
        armazenado = abs(eco.tamanho - sonda_resp.tamanho) <= oraculo.tolerancia and \
            abs(eco.tamanho - oraculo.referencia_tamanho) > oraculo.tolerancia
    else:
        armazenado = eco.digest == sonda_resp.digest and \
            eco.digest != oraculo.referencia_digest
    armazenado = armazenado or eco.status == sonda_resp.status != oraculo.referencia_status

    if not armazenado:
        return False, True, "resposta divergente nao foi armazenada pelo cache"

    limpa = cliente.buscar(aplicar_buster(oraculo.url, token(), oraculo.parametro_buster))
    if limpa.erro:
        return True, False, "nao foi possivel verificar o isolamento: %s" % limpa.erro

    if oraculo.pagina_dinamica:
        isolado = abs(limpa.tamanho - oraculo.referencia_tamanho) <= oraculo.tolerancia
    else:
        isolado = limpa.digest == oraculo.referencia_digest
    isolado = isolado and limpa.status == oraculo.referencia_status

    observacao = "" if isolado else (
        "ATENCAO: a chave de controle tambem retornou resposta divergente. "
        "Interromper o teste e verificar manualmente antes de prosseguir."
    )
    return True, isolado, observacao


def sondar_entradas(cliente: Cliente, oraculo: Oraculo, sondas, canario: str,
                    paralelas: int = 8, progresso=None):
    """Etapa 3 da metodologia: identificar entradas nao indexadas.

    Cada sonda recebe um cache-buster proprio. Nenhuma sonda compartilha chave
    de cache com outra nem com a requisicao de referencia.
    """
    def examinar(sonda):
        """Executa uma sonda. Independente das demais: cada uma tem buster proprio."""
        try:
            return _examinar(sonda)
        finally:
            if progresso is not None:
                progresso.sonda()

    def _examinar(sonda):
        buster = token()
        url = aplicar_buster(oraculo.url, buster, oraculo.parametro_buster)

        resp = cliente.buscar(url, cabecalhos={sonda.nome: sonda.valor})
        if resp.erro:
            return None

        sinal, refletido = houve_divergencia(oraculo, resp, canario)
        if not sinal:
            return None

        achado = Achado(
            url=oraculo.url,
            cabecalho=sonda.nome,
            valor=sonda.valor if len(sonda.valor) <= 64 else
                  "%s... (%d bytes)" % (sonda.valor[:32], len(sonda.valor)),
            classe=sonda.classe,
            tipo=sonda.tipo,
            sinal=sinal,
            status_referencia=oraculo.referencia_status,
            status_sonda=resp.status,
            tamanho_referencia=oraculo.referencia_tamanho,
            tamanho_sonda=resp.tamanho,
            refletido=refletido,
        )

        armazenado, isolado, observacao = confirmar_armazenamento(
            cliente, oraculo, url, resp
        )
        achado.armazenado = armazenado
        achado.isolado = isolado
        achado.observacao = observacao
        return achado

    # O laco sequencial deixava o orcamento de requisicoes ocioso durante o
    # tempo de ida e volta da rede: com RTT acima de 1/taxa, a sondagem
    # rodava abaixo do limite que lhe era permitido. Executar algumas sondas
    # em paralelo faz a triagem *alcancar* o orcamento, sem excede-lo, porque
    # o limitador por host continua sendo o teto.
    # Um pool por alvo, e nao um compartilhado: com pool unico, cada alvo em
    # Etapa 3 despeja todas as suas sondas numa fila comum e passa a esperar
    # tarefas de outros alvos, de modo que nenhum termina antes que a fila
    # inteira drene -- a execucao parece travada. Criar um pool por alvo custa
    # algumas threads, desprezivel diante de centenas de requisicoes de rede,
    # e so acontece nos poucos alvos que chegam ate aqui.
    if progresso is not None:
        progresso.entrar_sondagem()
    try:
        if paralelas <= 1:
            resultados = [examinar(sonda) for sonda in sondas]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=paralelas) as pool:
                resultados = list(pool.map(examinar, sondas))
    finally:
        if progresso is not None:
            progresso.sair_sondagem()

    return [achado for achado in resultados if achado is not None]


# --------------------------------------------------------------------------
# Orquestracao
# --------------------------------------------------------------------------


def normalizar_entrada(linha: str):
    linha = linha.strip()
    if not linha or linha.startswith("#"):
        return []
    if "://" in linha:
        return [linha]
    return ["https://%s%s" % (linha, caminho) for caminho in CAMINHOS_PADRAO]


def processar(cliente, url, sondas, canario, parametro,
              paralelas=8, progresso=None, modo=None):
    registro = {"url": url}

    if modo == 2:
        # Modo 2: a lista informada ja saiu de uma triagem (modo 1) e a Etapa 1
        # nao se repete. A Etapa 2 permanece obrigatoria, porque a Etapa 3
        # depende dela: e ela que fixa a resposta de referencia e que comprova
        # que o cache-buster integra a chave de cache, condicao para nao atingir
        # usuarios reais. Ela NAO confere se ha cache: uma URL informada sem
        # cache passa pela validacao, porque cada requisicao vai a origem, e as
        # sondas rodam sem efeito -- nada e armazenado que possa ser envenenado,
        # mas o tempo e gasto. Garantir que a lista tem cache e do usuario.
        alvo = Alvo(url=url, tem_cache=True, metodo_deteccao="informado pelo usuario",
                    evidencia="URL informada como tendo cache")
    else:
        alvo = detectar_cache(cliente, url)
    registro["etapa1"] = asdict(alvo)
    if not alvo.tem_cache:
        registro["conclusao"] = "sem cache confirmado"
        return registro

    oraculo, motivo = estabelecer_oraculo(cliente, alvo, parametro)
    if oraculo is None:
        registro["etapa2"] = {"oraculo": False, "motivo": motivo}
        registro["conclusao"] = "cache confirmado, oraculo seguro nao estabelecido"
        return registro

    registro["etapa2"] = {"oraculo": True, **asdict(oraculo)}

    # Parada antecipada: a Etapa 3 e ordens de grandeza mais cara que as duas
    # primeiras. Separar a triagem da sondagem permite varrer uma lista extensa
    # depressa e so depois investir tempo nos poucos alvos que a merecem.
    if modo == 1:
        registro["conclusao"] = "oraculo estabelecido"
        return registro

    achados = sondar_entradas(cliente, oraculo, sondas, canario,
                              paralelas, progresso)
    registro["etapa3"] = [asdict(a) for a in achados]

    confirmados = [a for a in achados if a.armazenado and a.isolado]
    if confirmados:
        registro["conclusao"] = "entrada nao indexada confirmada (%d)" % len(confirmados)
    elif achados:
        registro["conclusao"] = "divergencia observada sem armazenamento confirmado"
    else:
        registro["conclusao"] = "oraculo valido, nenhuma entrada nao indexada"
    return registro


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="wcpscan",
        description="Triagem automatizada de Web Cache Poisoning (Etapas 1 a 3).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    entrada = ap.add_mutually_exclusive_group(required=True)
    entrada.add_argument("-l", "--lista", help="arquivo com um host ou URL por linha")
    entrada.add_argument("-u", "--url", action="append", help="URL unica (repetivel)")

    ap.add_argument("-o", "--saida", help="arquivo JSON de saida")
    ap.add_argument("-w", "--wordlist", help="wordlist de cabecalhos candidatos",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "wordlists", "headers.txt"))
    ap.add_argument("-t", "--threads", type=int, default=16,
                    help="alvos processados em paralelo (padrao 16)")
    ap.add_argument("--rate", type=float, default=5.0,
                    help="limite de requisicoes por segundo POR HOST (padrao 5)")
    ap.add_argument("--rate-total", type=float, default=0.0, dest="rate_total",
                    help="teto global de requisicoes por segundo somando todos "
                         "os hosts; 0 desativa (padrao 0)")
    ap.add_argument("--sem-progresso", action="store_true", dest="sem_progresso",
                    help="nao exibir a linha de andamento em stderr")
    ap.add_argument("-m", "--mode", type=int, choices=(1, 2), default=None,
                    dest="modo", metavar="MODO",
                    help="1: Etapas 1 e 2 (cache e oraculo); "
                         "2: Etapa 3 sobre URLs que o usuario informa "
                         "como tendo cache, normalmente a saida do modo 1. "
                         "Sem -m, executa as tres etapas em sequencia")
    ap.add_argument("--salvar-alvos", dest="salvar_alvos", metavar="ARQUIVO",
                    help="grava, uma por linha, as URLs aprovadas: com oraculo "
                         "estabelecido no modo 1, com entrada nao indexada "
                         "confirmada nos demais; serve de entrada para -l")
    ap.add_argument("--sondas-paralelas", type=int, default=8,
                    dest="sondas_paralelas", metavar="N",
                    help="testes simultaneos dentro de um mesmo alvo (padrao 8); "
                         "o limite por host continua valendo como teto")
    ap.add_argument("--sem-cor", action="store_true", dest="sem_cor",
                    help="nao colorir a saida; a cor ja e desativada "
                         "automaticamente fora de terminal ou com NO_COLOR")
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--parametro", default="cb",
                    help="nome do parametro de cache-buster (padrao cb)")
    ap.add_argument("-k", "--insecure", action="store_true",
                    help="nao validar o certificado TLS")
    ap.add_argument("--sem-dos", action="store_true",
                    help="desabilitar os testes da trilha de disponibilidade")
    ap.add_argument("-v", "--verbose", type=int, nargs="?", const=1, default=0,
                    choices=(0, 1, 2), metavar="NIVEL",
                    help="0 (padrao) apenas os achados; 1 tambem os alvos com "
                         "cache confirmado; 2 todos os alvos examinados")
    args = ap.parse_args(argv)

    if args.lista:
        with open(args.lista, "r", encoding="utf-8", errors="replace") as fh:
            linhas = fh.readlines()
    else:
        linhas = args.url

    urls = []
    for linha in linhas:
        urls.extend(normalizar_entrada(linha))
    urls = list(dict.fromkeys(urls))
    if not urls:
        ap.error("nenhum alvo valido na entrada")

    canario = token(8)
    if args.modo == 1:
        # O modo 1 so le cabecalhos de resposta (Etapas 1 e 2). A wordlist
        # alimenta as sondas da Etapa 3 e nao e necessaria nem aberta aqui.
        sondas = []
    else:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="replace") as fh:
                cabecalhos = fh.read().splitlines()
        except OSError as exc:
            ap.error("nao foi possivel ler a wordlist: %s (indique outra com -w; "
                     "o modo 1 nao precisa dela)" % exc)
        sondas = montar_sondas(cabecalhos, canario, habilitar_dos=not args.sem_dos)

    limitador = LimitadorDeTaxa(args.rate, args.rate_total)
    cliente = Cliente(limitador, timeout=args.timeout,
                      verificar_tls=not args.insecure)

    hosts = len({urllib.parse.urlsplit(u).netloc.lower() for u in urls})
    print("wcpscan %s" % __version__, file=sys.stderr)
    # 2 requisicoes na Etapa 1, 3 na Etapa 2, uma por sonda na Etapa 3.
    if args.modo == 1:
        print("alvos: %d em %d host(s) | modo 1: Etapas 1 e 2"
              % (len(urls), hosts), file=sys.stderr)
    else:
        custo = (5 + len(sondas)) / args.rate if args.rate > 0 else 0.0
        rotulo = ("modo 2: Etapa 3 sobre URLs informadas como tendo cache | "
                  if args.modo == 2 else "")
        print("alvos: %d em %d host(s) | %stestes por alvo: %d (~%s por alvo "
              "com oraculo) | canario: %s"
              % (len(urls), hosts, rotulo, len(sondas),
                 Progresso._duracao(custo), canario),
              file=sys.stderr)
    print("taxa: %.1f req/s por host | teto global: %s | alvos em paralelo: %d "
          "| testes em paralelo: %d"
          % (args.rate,
             ("%.1f req/s" % args.rate_total) if args.rate_total > 0 else "sem teto",
             args.threads, args.sondas_paralelas), file=sys.stderr)
    print("cache-buster obrigatorio em todas as requisicoes (parametro '%s')"
          % args.parametro, file=sys.stderr)
    print("-" * 72, file=sys.stderr)

    resultados = []
    inicio = time.monotonic()
    cor = escolher_paleta(args.sem_cor)
    progresso = Progresso(len(urls), ativo=not args.sem_progresso)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.threads)
    interrompido = False
    try:
        futuros = {
            pool.submit(processar, cliente, url, sondas, canario, args.parametro,
                        max(1, args.sondas_paralelas), progresso,
                        args.modo): url
            for url in urls
        }
        for futuro in concurrent.futures.as_completed(futuros):
            url = futuros[futuro]
            try:
                registro = futuro.result()
            except Exception as exc:
                registro = {"url": url, "conclusao": "erro",
                            "erro": "%s: %s" % (type(exc).__name__, exc)}
            resultados.append(registro)
            progresso.limpar()
            relatar(registro, args.verbose, cor)
            progresso.passo(registro)
    except KeyboardInterrupt:
        # As threads estao bloqueadas em I/O de rede e nao respondem ao sinal.
        # Sem cancelar as pendentes e sem esperar, o atexit do executor tentaria
        # junta-las e o segundo Ctrl-C cairia num rastro de pilha.
        interrompido = True
        progresso.limpar()
        print("interrompido: gravando o que ja foi apurado...", file=sys.stderr)
        pool.shutdown(wait=False, cancel_futures=True)
    else:
        pool.shutdown(wait=True)
        # So seguro aqui: com wait=True, todas as threads do pool externo e,
        # por extensao, os pools de sondagem que cada uma abriu por alvo, ja
        # terminaram. No caminho interrompido as threads podem ainda estar
        # presas em I/O segurando uma conexao, e o processo esta de saida de
        # qualquer forma, entao fechar_tudo() e pulado ali.
        cliente.fechar_tudo()
    progresso.encerrar()

    resultados.sort(key=lambda r: r["url"])
    resumo = {
        "versao": __version__,
        "executado_em": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "duracao_s": round(time.monotonic() - inicio, 1),
        "alvos": len(urls),
        "com_cache": sum(1 for r in resultados if r.get("etapa1", {}).get("tem_cache")),
        "com_oraculo": sum(1 for r in resultados if r.get("etapa2", {}).get("oraculo")),
        "com_entrada_nao_indexada": sum(
            1 for r in resultados
            if any(a["armazenado"] and a["isolado"] for a in r.get("etapa3", []))
        ),
        "resultados": resultados,
    }

    print("-" * 72, file=sys.stderr)
    print("alvos %d | com cache %d | com oraculo %d | com entrada nao indexada %d | %.1fs"
          % (resumo["alvos"], resumo["com_cache"], resumo["com_oraculo"],
             resumo["com_entrada_nao_indexada"], resumo["duracao_s"]),
          file=sys.stderr)

    motivos = {}
    for r in resultados:
        if r.get("etapa3"):
            continue
        # A evidencia da Etapa 1 so explica a parada quando foi ela que parou o
        # alvo; para quem passou dela, quem explica e a Etapa 2 ou a conclusao.
        if r.get("etapa2", {}).get("motivo"):
            chave = r["etapa2"]["motivo"]
        elif not r.get("etapa1", {}).get("tem_cache"):
            chave = r.get("etapa1", {}).get("evidencia") or r.get("conclusao", "")
        else:
            chave = r.get("conclusao", "")
        if chave:
            motivos[chave] = motivos.get(chave, 0) + 1
    if motivos and args.verbose >= 1:
        print("onde a triagem parou:", file=sys.stderr)
        for chave, quantos in sorted(motivos.items(), key=lambda kv: -kv[1]):
            print("  %4d  %s" % (quantos, chave), file=sys.stderr)

    if args.salvar_alvos:
        # Criterio de aprovacao conforme o modo: o modo 1 termina na Etapa 2,
        # os demais terminam na Etapa 3.
        if args.modo == 1:
            aprovados = [r["url"] for r in resultados
                         if r.get("etapa2", {}).get("oraculo")]
            rotulo = "com oraculo estabelecido"
        else:
            aprovados = [r["url"] for r in resultados
                         if any(a["armazenado"] and a["isolado"]
                                for a in r.get("etapa3", []))]
            rotulo = "com entrada nao indexada"
        with open(args.salvar_alvos, "w", encoding="utf-8") as fh:
            for u in sorted(aprovados):
                fh.write(u + chr(10))
        print("%d alvo(s) %s gravados em %s"
              % (len(aprovados), rotulo, args.salvar_alvos), file=sys.stderr)

    if args.saida:
        with open(args.saida, "w", encoding="utf-8") as fh:
            json.dump(resumo, fh, ensure_ascii=False, indent=2)
        print("resultado gravado em %s" % args.saida, file=sys.stderr)
    else:
        # Sem -o, o JSON completo nao e jogado na tela: o resumo e os achados
        # ja foram mostrados por relatar() durante a execucao. Quem precisar
        # do registro detalhado por alvo deve pedir com -o.
        print("use -o arquivo.json para salvar o resultado detalhado",
              file=sys.stderr)

    if interrompido:
        # os._exit evita o atexit do executor, que tentaria juntar as
        # threads ainda presas em I/O e faria o processo pendurar.
        sys.stderr.flush()
        sys.stdout.flush()
        os._exit(130)

    return 0


class Progresso:
    """Indicador de andamento, em stderr, com repintura periodica.

    Contar apenas alvos concluidos nao basta: um alvo que chega a Etapa 3 com
    uma wordlist grande leva minutos, e durante esse tempo o contador fica
    parado e a execucao parece travada. Por isso o indicador mostra tambem
    quantos alvos estao em sondagem e quantas sondas ja foram enviadas.
    """

    LARGURA = 100
    INTERVALO = 0.2  # segundos entre repinturas, para nao competir com a saida

    def __init__(self, total: int, ativo: bool = True):
        self.total = total
        # Sem terminal interativo o retorno de carro so sujaria o arquivo.
        self.ativo = ativo and sys.stderr.isatty() and total > 0
        self.feitos = 0
        self.achados = 0
        self.sondas = 0
        self.sondando = 0
        self.inicio = time.monotonic()
        self._ultima_pintura = 0.0
        self._trava = threading.Lock()

    @staticmethod
    def _duracao(segundos: float) -> str:
        segundos = int(max(segundos, 0))
        if segundos < 60:
            return "%ds" % segundos
        if segundos < 3600:
            return "%dmin%02ds" % (segundos // 60, segundos % 60)
        return "%dh%02dmin" % (segundos // 3600, (segundos % 3600) // 60)

    def _linha(self) -> str:
        decorrido = time.monotonic() - self.inicio
        taxa = self.feitos / decorrido if decorrido > 0 else 0.0
        partes = ["[%d/%d] %5.1f%%" % (self.feitos, self.total,
                                       100.0 * self.feitos / self.total),
                  "achados %d" % self.achados]
        if self.sondando:
            # Enquanto ha sondagem em curso a estimativa por alvo nao vale:
            # um alvo em Etapa 3 custa centenas de vezes mais que um descartado.
            partes.append("%d na Etapa 3" % self.sondando)
            partes.append("%d testes" % self.sondas)
        else:
            partes.append("%.1f alvos/s" % taxa)
            restante = (self.total - self.feitos) / taxa if taxa > 0 else 0.0
            partes.append("restam ~%s" % self._duracao(restante))
        return "  ".join(partes)

    def _pintar(self, forcar: bool = False) -> None:
        """Repinta a linha. Deve ser chamado com a trava ja adquirida."""
        if not self.ativo:
            return
        agora = time.monotonic()
        if not forcar and agora - self._ultima_pintura < self.INTERVALO:
            return
        self._ultima_pintura = agora
        linha = self._linha()
        sys.stderr.write("\r" + linha[:self.LARGURA].ljust(self.LARGURA))
        sys.stderr.flush()

    def passo(self, registro) -> None:
        achou = any(a["armazenado"] and a["isolado"]
                    for a in registro.get("etapa3", []))
        with self._trava:
            self.feitos += 1
            if achou:
                self.achados += 1
            self._pintar(forcar=True)

    def entrar_sondagem(self) -> None:
        with self._trava:
            self.sondando += 1
            self._pintar(forcar=True)

    def sair_sondagem(self) -> None:
        with self._trava:
            self.sondando -= 1
            self._pintar(forcar=True)

    def sonda(self) -> None:
        with self._trava:
            self.sondas += 1
            self._pintar()

    def limpar(self) -> None:
        """Apaga a linha de progresso antes de escrever um resultado."""
        if self.ativo:
            sys.stderr.write("\r" + " " * self.LARGURA + "\r")
            sys.stderr.flush()

    def encerrar(self) -> None:
        if self.ativo:
            sys.stderr.write("\n")
            sys.stderr.flush()


CORES = {
    "achado": "\033[1;31m",   # vermelho forte: entrada nao indexada confirmada
    "cache": "\033[32m",      # verde: cache confirmado, sem achado
    "neutro": "\033[90m",     # cinza: alvo descartado
    "sonda": "\033[33m",      # amarelo: nome do cabecalho da sonda
    "fim": "\033[0m",
}
SEM_CORES = {chave: "" for chave in CORES}


def habilitar_ansi_windows() -> None:
    """Liga o processamento de sequencias ANSI no console do Windows.

    Sem isso, terminais legados do Windows imprimem os codigos de escape em
    bruto em vez de interpreta-los. Falhar aqui e inofensivo: a deteccao de
    terminal ja decide se a cor sera usada.
    """
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel = ctypes.windll.kernel32
        for identificador in (-11, -12):  # saida padrao e saida de erro
            handle = kernel.GetStdHandle(identificador)
            modo = ctypes.c_uint32()
            if kernel.GetConsoleMode(handle, ctypes.byref(modo)):
                kernel.SetConsoleMode(handle, modo.value | 0x0004)
    except Exception:
        pass


def escolher_paleta(desativar: bool):
    """Cor so quando faz sentido: terminal interativo e sem NO_COLOR."""
    if desativar or not sys.stdout.isatty() or os.environ.get("NO_COLOR") is not None:
        return SEM_CORES
    habilitar_ansi_windows()
    return CORES


def imprimivel(valor: str) -> str:
    """Escapa caracteres de controle no valor da sonda.

    A sonda de metacaractere usa bytes como NUL, que impressos em bruto
    corrompem a saida do terminal e a tornam ilegivel em registros e capturas.
    """
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in valor)


def relatar(registro, verbose: int = 0, cor=None):
    """Imprime o resultado de um alvo conforme o nivel de verbosidade.

    Nivel 0  apenas os alvos com entrada nao indexada confirmada
    Nivel 1  tambem os alvos em que a Etapa 1 confirmou cache, ainda que a
             triagem nao tenha chegado a um achado
    Nivel 2  todos os alvos examinados, inclusive os descartados por nao
             possuirem cache ou por terem falhado na requisicao
    """
    url = registro["url"]
    conclusao = registro.get("conclusao", "")
    achados = [a for a in registro.get("etapa3", []) if a["armazenado"] and a["isolado"]]
    tem_cache = bool(registro.get("etapa1", {}).get("tem_cache"))
    c = cor if cor is not None else SEM_CORES

    # flush explicito: sem terminal interativo o stdout usa buffer de bloco e
    # os achados so apareceriam ao final da execucao.
    if achados:
        print("%s[ACHADO]%s %s" % (c["achado"], c["fim"], url), flush=True)
        for a in achados:
            print("         %s%s%s: %s  [%s/%s]  %s"
                  % (c["sonda"], a["cabecalho"], c["fim"], imprimivel(a["valor"]),
                     a["classe"], a["tipo"], a["sinal"]),
                  flush=True)
            if a["observacao"]:
                print("         %s%s%s" % (c["neutro"], a["observacao"], c["fim"]),
                      flush=True)
    elif tem_cache and verbose >= 1:
        # O motivo da recusa do oraculo e mais informativo que a conclusao
        # generica: diz exatamente qual condicao da Etapa 2 nao foi satisfeita.
        detalhe = registro.get("etapa2", {}).get("motivo") or conclusao
        print("%s[CACHE ]%s %s  %s(%s)%s"
              % (c["cache"], c["fim"], url, c["neutro"], detalhe, c["fim"]),
              flush=True)
    elif verbose >= 2:
        evidencia = registro.get("etapa1", {}).get("evidencia") or ""
        detalhe = "%s: %s" % (conclusao, evidencia) if evidencia else conclusao
        print("%s[ .... ] %s  (%s)%s" % (c["neutro"], url, detalhe, c["fim"]),
              flush=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrompido pelo usuario", file=sys.stderr)
        sys.exit(130)
