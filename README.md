# wcpscan

Ferramenta e laboratório para detecção de **Envenenamento de Cache Web**
(*Web Cache Poisoning*, WCP).

Artefatos do Trabalho de Conclusão de Curso **"Envenenamento de Cache Web:
explorando falhas no design e na implementação de web cache em aplicações web
modernas"**, Instituto Federal da Paraíba, Curso
Superior de Tecnologia em Redes de Computadores, 2026.

| Diretório | Conteúdo |
|---|---|
| `wcpscan.py` | ferramenta de triagem, automatiza as Etapas 1 a 3 da metodologia |
| `wordlists/` | cabeçalhos candidatos a entrada não indexada |
| `lab/` | laboratório local com dez cenários de comportamento de cache |

Sem dependências. Apenas a biblioteca padrão do Python 3.9 ou superior.

## A metodologia

O trabalho propõe uma metodologia de cinco etapas para detecção e exploração
ética de WCP:

| Etapa | | Automatizada |
|---|---|---|
| 1 | Identificar se existe cache na aplicação web | sim |
| 2 | Identificar um oráculo, uma requisição específica sobre a qual o cache pode ser manipulado | sim |
| 3 | Verificar se existem entradas não indexadas (*unkeyed inputs*) que influenciam a resposta | sim |
| 4 | Explorar a entrada não indexada | não |
| 5 | Confirmar a exploração | não |

As Etapas 4 e 5 permanecem manuais porque exigem julgamento sobre o contexto da
reflexão, sobre o *gadget* aplicável e sobre o impacto real do achado. A
automação reduz o universo de análise, não substitui o pesquisador.

## Garantia ética

**Toda requisição carrega um cache-buster único, e não existe opção de desligar
esse comportamento.** Qualquer resposta divergente induzida pela triagem fica
presa a uma chave de cache que nenhum usuário legítimo solicita.

Três mecanismos sustentam a garantia:

1. **Isolamento por construção.** O parâmetro de cache-buster é adicionado à URL
   de cada requisição, com valor novo a cada sonda.
2. **Recusa quando o isolamento não é comprovável.** Antes de enviar qualquer
   sonda, a ferramenta verifica se o cache-buster realmente integra a chave de
   cache. Se não integrar, ou se o alvo não expuser sinal algum que permita
   decidir, o alvo é descartado.
3. **Verificação do isolamento após cada achado.** Confirmado o armazenamento da
   resposta divergente, a ferramenta requisita o recurso com um cache-buster
   novo e confere que a resposta legítima retorna. Se não retornar, o achado é
   marcado com aviso em vez de ser reportado como limpo.

A ferramenta não executa *payloads* de exploração e não tenta envenenar a chave
de cache real do recurso. O controle de taxa (`--rate`) é aplicado **por host**:
a proteção que importa é por alvo, de modo que hosts distintos não competem pela
mesma cota e a vazão total cresce com o número de alvos examinados em paralelo,
sem afrouxar o limite imposto a cada aplicação. Quando vários alvos compartilham
a mesma infraestrutura de origem, ou quando a banda do ponto de partida é
limitada, `--rate-total` impõe um teto global adicional.

**Use somente contra alvos que você está autorizado a testar**, seja um programa
de *bug bounty* com escopo explícito, seja infraestrutura própria, seja o
laboratório incluído neste repositório.

## Uso

    # lista de hosts, um por linha (host sozinho expande para os caminhos padrão)
    python wcpscan.py -l hosts.txt -o resultado.json

    # URL específica, com taxa conservadora
    python wcpscan.py -u https://alvo.example/static/app.js --rate 2

    # apenas a trilha de integridade, sem as sondas de disponibilidade
    python wcpscan.py -l hosts.txt --sem-dos

    # lista extensa: mais alvos simultâneos, cota por host inalterada
    python wcpscan.py -l 10k.txt -t 64 -o resultado.json

| Opção | Padrão | Função |
|---|---|---|
| `-l`, `--lista` | — | arquivo com um host ou URL por linha |
| `-u`, `--url` | — | URL única, repetível |
| `-o`, `--saida` | stdout | arquivo JSON de saída |
| `-w`, `--wordlist` | `wordlists/headers.txt` | cabeçalhos candidatos |
| `-t`, `--threads` | 16 | alvos processados em paralelo |
| `--rate` | 5 | requisições por segundo **por host** |
| `--rate-total` | 0 (sem teto) | teto global somando todos os hosts |
| `--sem-progresso` | desligado | oculta a linha de andamento em `stderr` |
| `--parametro` | `cb` | nome do parâmetro de cache-buster |
| `--sem-dos` | desligado | desabilita a trilha de disponibilidade |
| `-k`, `--insecure` | desligado | não validar o certificado TLS |
| `-v`, `--verbose` | 0 | nível de detalhe da saída, ver abaixo |
| `-m`, `--mode` | — | `1`: Etapas 1 e 2; `2`: Etapa 3 sobre URLs com cache; sem `-m`, as três |
| `--salvar-alvos` | — | grava as URLs aprovadas na última etapa executada |
| `--sondas-paralelas` | 8 | sondas simultâneas dentro de um mesmo alvo |
| `--sem-cor` | desligado | desliga a cor explicitamente |

### Níveis de saída

| Nível | Mostra | Marcador |
|---|---|---|
| `0` (padrão) | apenas alvos com entrada não indexada confirmada | `[ACHADO]` |
| `-v 1` | acrescenta os alvos em que a Etapa 1 confirmou cache | `[CACHE ]` |
| `-v 2` | acrescenta todos os demais, inclusive os sem cache | `[ .... ]` |

`-v` sozinho equivale a `-v 1`. Os marcadores têm largura fixa, de modo que as
URLs permanecem alinhadas na coluna seguinte.

Em terminal, os marcadores são coloridos — `[ACHADO]` em vermelho, `[CACHE ]` em
verde, `[ .... ]` em cinza — e o nome do cabeçalho da sonda aparece em amarelo. A
cor é desligada sozinha quando a saída não é um terminal, quando a variável
`NO_COLOR` está definida ou com `--sem-cor`, de modo que arquivos e *pipes* nunca
recebem sequências de escape.

### Dois modos: triagem e sondagem

A Etapa 3 custa uma requisição por sonda e é ordens de grandeza mais cara que as
duas primeiras. Para listas extensas, o fluxo recomendado usa os dois modos em
sequência:

    # modo 1: Etapas 1 e 2, de 2 a 5 requisições por alvo
    python wcpscan.py -l urls.txt -m 1 --salvar-alvos comcache.txt

    # modo 2: Etapa 3 sobre as URLs que o usuário informa como tendo cache
    python wcpscan.py -l comcache.txt -m 2 --salvar-alvos vulneraveis.txt -o resultado.json

| Modo | Etapas | Entrada |
|---|---|---|
| `-m 1` | 1 e 2 | qualquer lista de URLs |
| `-m 2` | 3 | URLs que **o usuário garante** terem cache, em geral a saída do modo 1 |
| sem `-m` | 1, 2 e 3 em sequência | qualquer lista de URLs |

`--salvar-alvos` grava as URLs aprovadas, uma por linha, no formato que `-l` lê:
com oráculo estabelecido no modo 1, com entrada não indexada confirmada nos
demais. No modo 1 a wordlist não é usada.

O modo 2 **não repete a Etapa 1**, mas mantém a validação do oráculo (Etapa 2),
porque a Etapa 3 depende dela: é ela que fixa a resposta de referência e comprova
que o cache-buster integra a chave de cache. Ela **não confere se há cache**. Uma
URL sem cache passa pela validação, as sondas rodam sem efeito, porque nada é
armazenado, e o tempo é desperdiçado. A responsabilidade pela lista é de quem a
informa.

`Ctrl-C` encerra de imediato e grava o resultado parcial (código de saída 130).

## Referências

- KETTLE, James. *Practical Web Cache Poisoning: Redefining 'Unexploitable'*.
  PortSwigger Research, 2018.
- KETTLE, James. *Web Cache Entanglement: Novel Pathways to Poisoning*.
  PortSwigger Research, 2020.
- NGUYEN, Hoai Viet; LO IACONO, Luigi; FEDERRATH, Hannes. *Your Cache Has
  Fallen: Cache-Poisoned Denial-of-Service Attack*. ACM CCS, 2019.
- LIANG, Yuejia et al. *Internet's Invisible Enemy: Detecting and Measuring Web
  Cache Poisoning in the Wild*. ACM CCS, 2024.
- FIELDING, R.; NOTTINGHAM, M.; RESCHKE, J. *RFC 9111: HTTP Caching*. IETF, 2022.

## Licença

MIT. Ver `LICENSE`.
