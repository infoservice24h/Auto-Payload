# Gerador Automático de Payload Android com Persistência e Ofuscação

---

<div align="center">

![Android Payload](https://img.shields.io/badge/Android-Payload-green?style=for-the-badge&logo=android)  
![Bash Script](https://img.shields.io/badge/Bash-Script-blue?style=for-the-badge&logo=gnu-bash)  
![Metasploit](https://img.shields.io/badge/Metasploit-Framework-red?style=for-the-badge&logo=metasploit)  

</div>

---

## Visão Geral

Este projeto oferece uma solução automatizada e interativa para a geração de payloads Android personalizados, com funcionalidades avançadas de persistência, ofuscação e assinatura digital. Desenvolvido para profissionais de segurança autorizados, o script `gerar_payload_auto.sh` guia o usuário passo a passo, desde a configuração inicial até o lançamento automático do handler Metasploit, simplificando processos complexos e garantindo eficiência máxima.

Se você é um pentester, analista de segurança ou entusiasta da área, esta ferramenta foi criada para facilitar a criação de payloads robustos, com proteção contra detecção e mecanismos para manter o acesso mesmo após reinicializações do dispositivo alvo.

---

## Parâmetros de Entrada e Automação

Durante a execução do script, você será solicitado a fornecer alguns parâmetros essenciais, mas o script agora automatiza a detecção do IP do servidor (LHOST) e sugere uma porta padrão (LPORT), facilitando o processo:

- **LHOST (Local Host):** O script detecta automaticamente o IP local da máquina (primeiro IP da interface principal) e o apresenta como valor padrão. Você pode simplesmente pressionar Enter para aceitar ou digitar outro IP.
- **LPORT (Local Port):** A porta padrão sugerida é `4444`, que pode ser aceita com Enter ou alterada conforme necessidade.
- **Nome do Pacote Android:** Identificador único do aplicativo Android, no formato padrão Java, como `com.payload.app`.
- **Caminho para o Keystore:** Arquivo keystore para assinatura digital do APK. Se não existir, o script gera um automaticamente.
- **Alias da Chave no Keystore:** Nome da chave dentro do keystore usada para assinar o APK.

Essa automação reduz erros e agiliza a configuração inicial.

---

## Ferramentas Integradas e Interação

O script interage com diversas ferramentas essenciais para o processo completo de criação do payload:

- **msfvenom:** Geração do payload Android com conexão reversa HTTPS.
- **apktool:** Descompilação e recompilação do APK para injeção de código e modificações.
- **keytool:** Criação e gerenciamento do keystore e chaves digitais.
- **apksigner:** Assinatura digital do APK final.
- **ProGuard:** Ofuscação do código para dificultar engenharia reversa.
- **dex2jar:** Conversão entre `.dex` e `.jar` para facilitar a ofuscação.
- **wget, unzip, sed:** Utilitários para download, extração e manipulação de arquivos.

O script verifica e instala automaticamente as dependências necessárias para a ofuscação, tornando o processo mais acessível.

---

## Diferenciais e Vantagens

Este gerador de payloads Android se destaca por unir diversas etapas complexas em um único fluxo automatizado e interativo, com benefícios claros:

- **Automação Completa:** Desde a geração do payload até o início do handler Metasploit, tudo é feito automaticamente, poupando tempo e reduzindo erros manuais.
- **Detecção Automática do IP:** Facilita a configuração inicial, evitando erros de digitação e agilizando o processo.
- **Persistência Garantida:** Inclusão do `BootReceiver` para ativação automática após reinicializações.
- **Ofuscação Integrada:** Técnicas que aumentam a resistência à análise e detecção.
- **Assinatura Digital:** APK assinado para instalação em dispositivos Android modernos.
- **Interatividade e Validação:** Orientação e validação das entradas do usuário.
- **Instalação Automática de Dependências:** Facilita o uso mesmo para quem não tem todas as ferramentas pré-instaladas.

---

## Possibilidades e Aplicações

Profissionais de segurança podem criar payloads Android personalizados para testes de penetração em ambientes controlados, simulando ataques reais e avaliando a segurança de dispositivos móveis. A persistência e ofuscação aumentam a fidelidade dos testes, permitindo análises mais profundas sobre a resistência dos sistemas alvo.

O script pode ser adaptado para incluir outros tipos de payloads, protocolos de comunicação ou técnicas de evasão, tornando-se uma base poderosa para projetos avançados de segurança móvel.

---

## Requisitos

- Sistema Linux (preferencialmente Debian/Ubuntu)
- `msfvenom` e `msfconsole` (Metasploit Framework)
- `apktool`
- `keytool` (Java Development Kit)
- `apksigner` (Android SDK Build Tools)
- `wget`, `unzip`, `sed`, `bash`
- Permissões para instalar pacotes via `apt` (para ProGuard e outras dependências)

---

## Como Usar

1. Clone este repositório:
   ```bash
   git clone https://github.com/seuusuario/gerador-payload-android.git
   cd gerador-payload-android
