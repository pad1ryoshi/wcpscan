# Laboratório de Envenenamento de Cache Web

Emula um cache intermediário ingênuo na frente de um servidor de origem, em dez
cenários de comportamento distintos. Serve para validar a metodologia de cinco
etapas e a ferramenta `wcpscan` sem tocar em nenhum alvo externo.

> O laboratório é **deliberadamente vulnerável**. Ele escuta em `127.0.0.1` por
> padrão e não deve ser exposto na rede.

## Execução

    python lab.py                 # http://127.0.0.1:8099
    python lab.py --porta 9000
    python lab.py --listar        # imprime a tabela de cenários e sai

A raiz (`/`) serve um índice navegável com todos os cenários.

## Desenho

Os cenários se dividem em três grupos.

**Vulneráveis (4).** A entrada não indexada existe e é explorável. A ferramenta
deve reportar.

**Controles negativos (4).** Há cache e há entrada que influencia a resposta,
mas não há envenenamento. Cada controle reproduz um motivo diferente para que
não haja: o cabeçalho é indexado via `Vary`, o cache rejeita a resposta de erro,
o recurso não é cacheável, ou a resposta varia naturalmente a cada requisição.
A ferramenta **não** deve reportar.

**Recusas de oráculo (2).** O cache ignora o parâmetro de cache-buster, de modo
que o isolamento dos testes não pode ser comprovado. A ferramenta deve recusar o
alvo **antes** de enviar qualquer sonda.

Os controles negativos são a parte deliberada do desenho. Um laboratório
composto apenas de cenários vulneráveis mediria somente a **sensibilidade** do
método, isto é, a capacidade de encontrar a falha que o próprio autor plantou.
Com os controles, mede-se também a **especificidade**: a capacidade de não
acusar falha onde não há. É a diferença entre um laboratório que confirma o que
se quer ouvir e um laboratório que pode reprovar o método.

## Cenários

### Vulneráveis

| Rota | Trilha | Comportamento | Sinal esperado |
|---|---|---|---|
| `/vuln/unkeyed-header` | integridade | `X-Forwarded-Host` não indexado, refletido em `<script src>`. Cache anuncia `X-Cache` | reflexão do valor na resposta |
| `/vuln/hmo` | disponibilidade | origem honra `X-HTTP-Method-Override` e devolve **200 com corpo vazio**. Cache sem estado declarado, apenas `Age` | divergência de corpo, **sem reflexão** |
| `/vuln/hho` | disponibilidade | cabeçalho acima de 4 KiB gera `400` e o cache armazena o erro | divergência de status |
| `/vuln/hmc` | disponibilidade | metacaractere em cabeçalho gera `400` armazenado. Cache sem estado e **sem `Age`** | divergência de status |

O cenário `/vuln/hmo` é o que corresponde ao caso estudado no trabalho, e é o
mais exigente dos quatro por duas razões. O artefato armazenado **não é uma
resposta de erro**, é um `200` com corpo vazio: qualquer detecção baseada em
código de status o deixa passar. E não há reflexão alguma do valor enviado:
qualquer critério que exija reflexão o classifica como não explorável.

Os três cenários de disponibilidade correspondem às variantes HHO, HMC e HMO do
*Cache Poisoned Denial of Service* descrito por Nguyen, Lo Iacono e Federrath
(2019).

### Controles negativos

| Rota | Por que não é vulnerável |
|---|---|
| `/controle/vary` | `X-Forwarded-Host` influencia a resposta, porém o cache o **indexa** via `Vary`. Cada valor gera entrada própria, então a resposta manipulada nunca é servida a quem não a pediu |
| `/controle/erro-nao-armazenado` | o cabeçalho sobredimensionado gera `400`, mas o cache **recusa armazenar** resposta de erro. A divergência existe e não persiste |
| `/controle/sem-cache` | recurso declarado `no-store`. Não há cache intermediário atuando, logo não há superfície |
| `/controle/dinamico` | a borda injeta um identificador de tamanho variável em cada resposta. O corpo nunca é idêntico, e a variação natural não deve ser lida como divergência induzida |

Os dois primeiros são os controles mais importantes: neles a ferramenta
**observa** a divergência e ainda assim não reporta, porque a etapa de
confirmação não comprova o armazenamento indevido. É exatamente a distinção
entre "a entrada influencia a resposta" e "a entrada envenena o cache".

### Recusas de oráculo

| Rota | Por que o oráculo é recusado |
|---|---|
| `/recusa/query-ignorada` | o cache não inclui a query string na chave. O cache-buster não isola o teste, então sondar o alvo afetaria usuários reais |
| `/recusa/cache-mudo` | o cache ignora a query string **e** não emite estado nem `Age`. Só o cabeçalho `Date`, repassado da origem, denuncia o reaproveitamento da entrada |

## Resultado da validação

Execução de 05/10/2026, contra os dez cenários:

    python lab/lab.py &
    python wcpscan.py -l alvos.txt --rate 60 -v

    alvos 10 | com cache 9 | com oraculo 7 | com entrada nao indexada 4 | 7.8s

| Grupo | Cenários | Reportados | Esperado | Resultado |
|---|---|---|---|---|
| vulneráveis | 4 | 4 | 4 | sem falso negativo |
| controles negativos | 4 | 0 | 0 | sem falso positivo |
| recusas de oráculo | 2 | 0 | 0 | recusa correta antes de sondar |

Achados reportados, por trilha:

| Rota | Cabeçalho | Sinal |
|---|---|---|
| `/vuln/unkeyed-header` | `X-Forwarded-Host` | reflexão do valor na resposta |
| `/vuln/hmo` | `X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method` | divergência de corpo, 114 para 0 bytes |
| `/vuln/hho` | `X-Oversized-Header` (8 KiB) | divergência de status, 200 para 400 |
| `/vuln/hmc` | `X-Metachar-Header` | divergência de status, 200 para 400 |

## Como o laboratório é construído

Cada cenário é um registro declarativo (`Cenario`) que combina uma função de
origem com o comportamento do cache: se a query string integra a chave, se o
`X-Forwarded-Host` integra a chave, se respostas de erro são armazenadas, quais
cabeçalhos de cache são emitidos, qual o TTL, e se a borda injeta identificador
por resposta.

A função `chave_de_cache` é o coração do laboratório. É exatamente a divergência
entre o que entra nela e o que a origem efetivamente consome que determina se o
cenário é vulnerável. Acrescentar um cenário novo é acrescentar um registro à
lista `CENARIOS`.

O cache reproduz um detalhe que importa: ao servir do próprio armazenamento, ele
repassa ao cliente a `Date` gerada pela origem, em vez de gerar uma nova. É esse
comportamento que permite decidir se o cache-buster integra a chave quando o
alvo não expõe estado de cache nem `Age`.
