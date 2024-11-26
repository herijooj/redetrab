# Códigos

### Códigos de Retorno
| Tipo  | Definição       |
|-------|-----------------|
| 00100 | Backup          |
| 00001 | Nack            |
| 00010 | Ok              |
| 01111 | Tamanho         |
| 11111 | Erro            |
| 10000 | Dados           |
| 10001 | Fim TX Dados    |
| 01110 | OK + Tam        |
| 01101 | OK + Checksum   |

### Códigos:
1. Sem Acesso
2. Sem Espaço
3. Não Encontrado

### Detalhes
Não usar Bitfields.
Timeout Obrigatório.
CRC de 8 bits.
Para e espera.