# Simulador de Anel de Token

Esta aplicação Python simula uma rede em anel de token usando UDP para transmissão de mensagens entre nós. Implementa passagem de token, enfileiramento de mensagens, verificação de erro CRC32, injeção de falhas e funcionalidades básicas de unicast/broadcast conforme os requisitos do projeto final de Redes de Computadores.

## Funcionalidades

-   **Passagem de Token:** Um token circula pelo anel, permitindo apenas ao portador transmitir dados.
-   **Fila de Mensagens:** Cada nó possui uma fila de mensagens (máximo 10 mensagens).
-   **Comunicação UDP:** Todos os pacotes (token e dados) são enviados via UDP.
-   **Formatos de Pacote:** Adere à especificação da tarefa - token (`9000`) e dados (`7777:<status>;<origem>;<destino>;<CRC>;<mensagem>`).
-   **Controle de Erro CRC32:** Pacotes de dados incluem uma soma de verificação CRC32 para integridade da mensagem.
-   **ACK/NACK/NAOEXISTE:** Manipula diferentes estados para entrega de mensagens conforme especificado.
-   **Retransmissão:** Retransmite pacotes com NACK apenas uma vez.
-   **Injeção de Falhas:** Injeção de falhas automática (10% de probabilidade) e manual. Para broadcast, o status permanece `naoexiste`.
-   **Broadcast:** Suporta envio de mensagens para todos os nós usando o apelido `TODOS`.
-   **Controle de Token:** O nó gerador designado gerencia perda de token (timeout) e detecção de duplicatas.
-   **Arquivo de Configuração:** Parâmetros do nó carregados do arquivo de configuração seguindo o formato exato da tarefa.
-   **Interface de Linha de Comando:** CLI abrangente com recursos de depuração e monitoramento.

## Estrutura de Arquivos

-   `ring_node.py`: O script Python principal que executa cada nó na simulação.
-   `config_A.txt`, `config_B.txt`, `config_C.txt`: Arquivos de configuração de exemplo para anel de 3 nós (Alice → Bob → Charlie → Alice).
-   `test_ring.sh`: Script de teste com instruções para executar a demonstração de 3 nós.

## Como Executar

1.  **Pré-requisitos:**
    *   Python 3.12+ (ou use `uv run` com ambiente virtual)

2.  **Arquivos de Configuração:**
    Cada nó requer um arquivo de configuração seguindo a **especificação exata da tarefa** (4 linhas):

    ```
    <token_destination_ip>:porta
    <apelido_da_máquina_atual>
    <tempo_token>
    <gerador_token_true_ou_false>
    ```

    **Exemplo `config_A.txt` (Alice - Gerador de Token):**
    ```
    127.0.0.1:6002
    Alice
    1
    true
    ```
    **Exemplo `config_B.txt` (Bob):**
    ```
    127.0.0.1:6003
    Bob
    1
    false
    ```
    **Exemplo `config_C.txt` (Charlie):**
    ```
    127.0.0.1:6001
    Charlie
    1
    false
    ```

    **Topologia do anel:** Alice (6001) → Bob (6002) → Charlie (6003) → Alice

3.  **Executando o Script:**
    **IMPORTANTE:** O argumento `--port` é **obrigatório** para cada nó especificar sua porta de escuta.

    **Sintaxe do comando:**
    ```bash
    uv run python ring_node.py --config <arquivo_config> --port <porta_escuta>
    ```
    ou
    ```bash
    python ring_node.py --config <arquivo_config> --port <porta_escuta>
    ```

    **Para Teste Local (3 terminais):**
    ```bash
    # Terminal 1 (Alice - Gerador de Token)
    uv run python ring_node.py --config config_A.txt --port 6001

    # Terminal 2 (Bob)
    uv run python ring_node.py --config config_B.txt --port 6002

    # Terminal 3 (Charlie)
    uv run python ring_node.py --config config_C.txt --port 6003
    ```

    **Para Configuração Multi-Máquina:**
    Cada máquina executa com sua própria porta de escuta e arquivo de configuração apontando para a próxima máquina no anel.

    O nó gerador de token criará e enviará automaticamente o primeiro token após um breve atraso.

4.  **Comandos do Usuário:**
    Uma vez que um nó esteja executando, você pode usar estes comandos:

    **Comandos Básicos:**
    - `send <apelido> <mensagem>` - Enviar mensagem para nó específico
    - `send TODOS <mensagem>` - Broadcast mensagem para todos os nós
    - `queue` - Mostrar fila de mensagens atual
    - `token` - Mostrar status do token
    - `status` - Mostrar informações detalhadas do nó
    - `quit` - Sair do programa

    **Comandos de Depuração:**
    - `faultmode on|off` - Habilitar/desabilitar injeção de falhas para próxima mensagem
    - `verbose on|off` - Controlar log verboso (mostra encaminhamento de pacotes)
    - `gentoken` - Gerar manualmente um novo token
    - `stoptoken` - (Apenas gerador) Parar token para depuração

5.  **Configuração de Rede (para multi-máquina):**
    *   Certifique-se de que todas as máquinas estão na mesma rede local.
    *   Configure firewalls do SO para permitir tráfego UDP de entrada nas portas especificadas.
    *   Verifique se a configuração de cada nó aponta para o IP e porta corretos do próximo vizinho.

## Exemplo de Sessão de Teste

```bash
# Iniciar o auxiliar de teste
./test_ring.sh

# Executar em 3 terminais conforme mostrado, então tente estes comandos:

[Alice]> send Bob Olá do Alice
[Alice]> send TODOS Broadcast para todos  
[Alice]> faultmode on
[Alice]> send Charlie Esta mensagem será corrompida
[Alice]> status
[Alice]> queue
```

## Detalhes de Implementação

-   **Conformidade com a Tarefa:** Segue os formatos de pacote exatos e configuração especificados na tarefa.
-   **Concorrência:** Usa módulo `threading` para listener UDP e detecção de timeout de token.
-   **CRC32:** Usa `zlib.crc32` para cálculo e verificação de controle de erro.
-   **Análise de Pacotes:** Análise baseada em string com delimitadores de ponto e vírgula (`;`).
-   **Controle de Token:** Detecção de perda de token baseada em timer e prevenção de duplicatas.
-   **Tratamento de Erros:** Tratamento abrangente de erros para problemas de rede e pacotes malformados.

## Recursos Principais para Demonstração da Tarefa

1.  **Visualização de Passagem de Token:** Mostra movimento do token pelo anel
2.  **Encaminhamento de Mensagens:** Exibe quando nós encaminham pacotes (modo verboso)
3.  **Detecção e Recuperação de Erros:** Validação CRC e retransmissão
4.  **Injeção de Falhas:** Automática e manual para testes
5.  **Suporte a Broadcast:** Apelido `TODOS` para mensagens para toda a rede
6.  **Monitoramento de Rede:** Comandos de status mostram saúde do anel e localização do token

## Observações

-   **Conteúdo da Mensagem:** Evite ponto e vírgula (`;`) nas mensagens pois são usados como delimitadores de pacote.
-   **Cálculo CRC:** CRC32 é calculado apenas no conteúdo da mensagem.
-   **Requisitos de Porta:** Cada nó deve usar uma porta de escuta única.
-   **Formato da Tarefa:** Arquivos de configuração seguem estritamente o formato de 4 linhas especificado na tarefa. 