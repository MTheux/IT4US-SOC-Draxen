# Experiência do cliente — visão EASM

**Versão:** 1.0  
**Data:** 2026-11-05  
**Estado:** interface web v1.0 implementada para overview, inventário, exposições compartilhadas, mudanças, relatórios e troca de projeto. Funciona com dados sintéticos; validação de acesso de cliente e conteúdo em um piloto seguem pendentes.

## Objetivo da tela

Permitir que o cliente entenda, em poucos minutos, quais ativos externos estão associados ao seu projeto, o que mudou desde o último período, quais itens exigem atenção e o que a equipe do SOC já revisou.

## Página inicial do projeto

### Resumo superior — implementado

- **Ativos acompanhados:** contagem com link para inventário.
- **Novos desde o último período:** contagem de candidatos, separando candidatos ainda não revisados.
- **Exposições em triagem:** contagem por prioridade.
- **Ações concluídas:** decisões e correções registradas pelo SOC/cliente.
- **Última atualização:** data/hora e fonte; sinalizar atraso na coleta.

### Mudanças recentes — implementado

Lista cronológica: hostname/ativo, tipo de mudança, quando foi observado, fonte, confiança e estado da revisão.

### Prioridades

Fila resumida com título, prioridade, ativo, explicação, estado e próxima ação. A interface deve mostrar a razão da prioridade e distinguir:

- `Observado`: dado externo de fornecedor, sem confirmação própria.
- `Candidato`: associação ao projeto ainda em revisão.
- `Validado`: confirmado por revisão técnica apropriada, com evidência e data.
- `Descartado`: falso positivo ou fora do escopo, com razão registrada.
- `Ação recomendada`: orientação defensiva; não implica que uma falha foi explorada.

### Inventário — implementado

Filtros por tipo de ativo, ambiente, relação com seed, confiança, fonte e estado. Exibir relações indiretas e possível infraestrutura compartilhada, sem apresentar IP compartilhado como propriedade exclusiva.

## Página de exposição

- O que foi observado e por qual fonte.
- Timestamp da observação e timestamp de ingestão.
- Ativo e evidência técnica sanitizada.
- Por que foi associado ao projeto, com confiança e relação usada.
- Risco operacional e fatores que formaram a prioridade.
- O que não foi validado e quais incertezas permanecem.
- Histórico da triagem e recomendações.
- Ação sugerida e responsável, sem botão que inicie scan ou exploração.

## Relatório mensal

1. Resumo executivo em linguagem simples.
2. Inventário coberto e limitações da fonte.
3. Mudanças relevantes do período.
4. Exposições revisadas, decisões, prioridades e recomendações.
5. Itens ainda pendentes, bloqueados ou fora do escopo.
6. Metodologia, fontes e datas de coleta.
7. Declaração explícita de que a ausência de registro não comprova ausência de ativo ou risco.

## Privacidade e acesso

- A conta do cliente vê somente os projetos explicitamente atribuídos.
- Não exibir tokens, chaves, dados pessoais, logs internos, notas internas do SOC ou dados de outros clientes.
- Evidências e exportações passam por sanitização e revisão humana.
- Downloads e compartilhamentos ficam registrados em auditoria.
- O modo inicial é privado e autenticado; acesso público não é padrão.

## Indicadores de sucesso de UX

- Cliente distingue observação de validação sem apoio do analista.
- Cada prioridade mostra a razão e a próxima ação.
- Um usuário não consegue abrir ativos de outro tenant alterando URL ou identificador.
- Exportação representa o estado e a data da evidência sem omitir limitações.
