---
title: "Rede Em Anel Com Controle De Acesso Por Passagem De Bastão"
author: Heric Camargo 
date: GRR20203959
---

# Relatório Do Projeto: Rede Em Anel Com Controle De Acesso Por Passagem De Bastão

## Estrutura Das Mensagens

- `TOKEN`: Indica a posse do token.
- `GAME_START`: Inicia uma nova partida do jogo.
- `PLAYER_ACTION`: Representa uma ação tomada por um jogador.
- `GAME_STATE`: Atualiza o estado atual do jogo.
- `GAME_FINISHED`: Indica o término do jogo.

Além disso, mensagens relacionadas ao estado do jogo incluem campos adicionais como `state`, `initiator`, `player`, e `action` para detalhar o conteúdo da comunicação.

## Sincronização Do Estado Do Jogo

O estado do jogo é mantido de forma centralizada e sincronizado entre todas as máquinas através de mensagens `GAME_STATE`. Cada alteração no estado é propagada pelo anel, garantindo que todas as máquinas tenham uma visão consistente do jogo.

## Fluxo Do Jogo

1. **Início do Jogo**: A máquina com índice 0 inicia o jogo ao receber o token inicial.
2. **Distribuição de Cartas**: Cada jogador recebe duas cartas e o dealer recebe duas cartas.
3. **Turno dos Jogadores**: Cada jogador, na sua vez, pode escolher entre ações como HIT, STAND, DOUBLE ou SURRENDER.
4. **Turno do Dealer**: Após todos os jogadores, o dealer joga seguindo as regras do Blackjack.
5. **Resultados**: Os resultados são calculados e exibidos para cada jogador.

## Implementação Técnica

## Uso Do Bastão

O bastão (`TOKEN`) controla o acesso exclusivo aos recursos. Apenas quem o possui pode processar ações ou iniciar o jogo.

### Estado Do Jogo

- **Deck**: Cartas restantes.
- **Players**: Lista com `cards`, `status`, `can_double` e `can_surrender`.
- **Dealer**: Cartas do dealer.
- **Current Player**: Jogador atual.
- **Status**: Estado (`waiting`, `active`, `finished`).

#### Exemplo De Estado

```python
self.game_state = {
    'deck': [],
    'players': [{'cards': [], 'status': 'active', 'can_double': True}],
    'dealer': [],
    'current_player': 0,
    'status': 'waiting'
}
```