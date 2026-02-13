#!/usr/bin/env bash

# ==========================================
# TRIAGEMASTER
# Author: Sanmir Gabriel
# Flow: Subfinder -> Naabu -> ScopeSentry -> GAU -> Nuclei -> GoWitness
# ==========================================

# 1️⃣ BASH STRICT MODE
# -e: Sai se houver erro
# -u: Sai se variável não existir
# -o pipefail: Sai se qualquer comando no pipe falhar
set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

# 2️⃣ TRAP (CLEANUP)
trap 'echo -e "\n${RED}[!] Execução interrompida pelo usuário (SIGINT). Saindo...${RESET}"; exit 1' INT

RAW_INPUT=${1:-} # Tratamento para set -u (se $1 for vazio, não quebra aqui, verificamos abaixo)
DATE=$(date +%Y-%m-%d)
SECONDS=0

banner() {
    echo -e "${BLUE}"
    echo "  _____      _                       __  __            _             "
    echo " |_   _|__ (_) __ _  __ _  ___    |  \/  | __ _ ___| |_ ___ _ __ "
    echo "   | || '__| |/ _\` |/ _\` |/ _ \   | |\/| |/ _\` / __| __/ _ \ '__|"
    echo "   | || |  | | (_| | (_| |  __/   | |  | | (_| \__ \ ||  __/ |   "
    echo "   |_||_|  |_|\__,_|\__, |\___|   |_|  |_|\__,_|___/\__\___|_|   "
    echo "                    |___/                     by: san ^^           "
    echo -e "${RESET}"
}

check_deps() {
    local tools=("subfinder" "naabu" "scopesentry" "jq" "nuclei" "gau" "uro" "gowitness")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then 
            echo -e "${RED}[X] Erro Crítico: '$tool' não está instalado ou não está no PATH.${RESET}"
            exit 1
        fi
    done
}

# Validação de Input
if [ -z "$RAW_INPUT" ]; then
    banner
    echo "Uso: ./triage.sh <alvo.com>"
    exit 1
fi

# Extração limpa do domínio
DOMAIN=$(echo "$RAW_INPUT" | sed -E 's|^https?://||I; s|/.*||; s|:.*||')

if ! [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    echo -e "${RED}[X] Input inválido: $DOMAIN${RESET}"
    exit 1
fi

WORKSPACE="recon/${DOMAIN}_${DATE}"

banner
check_deps
mkdir -p "$WORKSPACE"

# 5️⃣ LOGGING (Tee: tela + arquivo)
LOG_FILE="$WORKSPACE/execution.log"
echo -e "${BLUE}[i] Log da execução será salvo em: $LOG_FILE${RESET}"
exec > >(tee -a "$LOG_FILE") 2>&1

echo -e "${YELLOW}[*] Iniciando Triagem: $DOMAIN${RESET}"
echo -e "${BLUE}[i] Workspace: $WORKSPACE${RESET}"

# ---------------------------------------------------------
# 1. SUBDOMÍNIOS
# ---------------------------------------------------------
echo -e "\n${GREEN}[1/6] Subfinder (Enumerando DNS)...${RESET}"

subfinder -d "$DOMAIN" -silent -all > "$WORKSPACE/subs_raw.txt" || { echo -e "${RED}[X] Subfinder falhou!${RESET}"; exit 1; }

# 3️⃣ DEDUPLICAÇÃO
if [ -s "$WORKSPACE/subs_raw.txt" ]; then
    sort -u "$WORKSPACE/subs_raw.txt" -o "$WORKSPACE/subs_raw.txt"
    echo -e "    -> Encontrados (Deduplicados): $(wc -l < "$WORKSPACE/subs_raw.txt")"
else
    echo -e "${RED}[!] Nenhum subdomínio encontrado. Abortando.${RESET}"
    exit 1
fi

# ---------------------------------------------------------
# 2. PORT SCAN (Infraestrutura) 
# ---------------------------------------------------------
echo -e "\n${GREEN}[2/6] Naabu (Portas Críticas Web & Infra)...${RESET}"

naabu -list "$WORKSPACE/subs_raw.txt" \
      -p 21,22,23,25,53,80,110,139,443,445,1433,3306,3389,5432,6379,8000,8080,8443,9000,9200 \
      -silent > "$WORKSPACE/ports.txt" || { echo -e "${RED}[X] Naabu falhou!${RESET}"; exit 1; }

if [ ! -s "$WORKSPACE/ports.txt" ]; then
    echo -e "${RED}[!] Nenhuma porta aberta encontrada.${RESET}"
    exit 1
fi

# Obs: Com 'set -e', se o grep não achar nada, ele retorna 1 e mata o script.
# Adicionamos '|| true' para garantir continuidade.
grep -E ":(21|22|23|25|445|1433|3306|3389|5432|6379)$" "$WORKSPACE/ports.txt" > "$WORKSPACE/infra_exposed.txt" || true

if [ -s "$WORKSPACE/infra_exposed.txt" ]; then
    echo -e "${RED}[!!!] PERIGO: Serviços de Infraestrutura Abertos!${RESET}"
    cat "$WORKSPACE/infra_exposed.txt"
else
    echo -e "${BLUE}[i] Nenhuma infraestrutura crítica (SSH/DB) exposta publicamente.${RESET}"
fi

# ---------------------------------------------------------
# 3. VALIDAÇÃO WEB (ScopeSentry)
# ---------------------------------------------------------
echo -e "\n${GREEN}[3/6] ScopeSentry (Validando HTTP/S)...${RESET}"

# ScopeSentry pode falhar se o arquivo ports estiver mal formatado, tratamos o erro
scopesentry -c 100 -t 3 -L -json < "$WORKSPACE/ports.txt" > "$WORKSPACE/alive.json" || { echo -e "${RED}[X] ScopeSentry falhou!${RESET}"; exit 1; }

# Verifica se o JSON é válido antes de parsear
if jq empty "$WORKSPACE/alive.json" >/dev/null 2>&1; then
    jq -r .url "$WORKSPACE/alive.json" > "$WORKSPACE/urls.txt"
else
    echo -e "${RED}[X] Erro: JSON inválido gerado pelo ScopeSentry.${RESET}"
    # Não damos exit aqui para tentar continuar com o que tiver, mas é arriscado com set -e.
    # Vamos criar urls.txt vazio para não quebrar o resto.
    touch "$WORKSPACE/urls.txt"
fi

COUNT_ALIVE=$(wc -l < "$WORKSPACE/urls.txt")
echo -e "    -> Web Services Vivos: $COUNT_ALIVE"

# ---------------------------------------------------------
# 4. MINERAÇÃO HISTÓRICA (GAU + URO)
# ---------------------------------------------------------
echo -e "\n${GREEN}[4/6] GAU (Minerando URLs Antigas)...${RESET}"

echo -e "${BLUE}[i] Baixando e Limpando com URO...${RESET}"

# Pipefail vai pegar erro aqui se gau ou uro falharem
gau "$DOMAIN" --subs --threads 5 | uro > "$WORKSPACE/gau_clean.txt" || echo -e "${YELLOW}[!] GAU retornou erro, verificando output parcial...${RESET}"

touch "$WORKSPACE/gau_vivas.txt" "$WORKSPACE/params_sqli.txt"

if [ -s "$WORKSPACE/gau_clean.txt" ]; then
    echo -e "${BLUE}[i] Validando existência com ScopeSentry...${RESET}"
    
    # Adicionado || true para evitar crash se ScopeSentry retornar erro em URLs malucas
    scopesentry -c 50 -t 5 -mc 200,301,302,403,500 -json < "$WORKSPACE/gau_clean.txt" > "$WORKSPACE/gau_alive.json" || true
    
    if [ -s "$WORKSPACE/gau_alive.json" ] && jq empty "$WORKSPACE/gau_alive.json" >/dev/null 2>&1; then
        jq -r .url "$WORKSPACE/gau_alive.json" > "$WORKSPACE/gau_vivas.txt"
        echo -e "    -> URLs Históricas Vivas: $(wc -l < "$WORKSPACE/gau_vivas.txt")"
        
        echo -e "${BLUE}[i] Buscando parâmetros suspeitos...${RESET}"
        grep -E '\?.+=' "$WORKSPACE/gau_vivas.txt" > "$WORKSPACE/params_sqli.txt" || true
    fi
else
    echo -e "${YELLOW}[!] GAU não encontrou URLs ou falhou.${RESET}"
fi

# ---------------------------------------------------------
# 5. VISUAL RECON (Screenshots)
# ---------------------------------------------------------
echo -e "\n${GREEN}[5/6] GoWitness (Tirando Prints)...${RESET}"

# Combina e remove duplicatas
cat "$WORKSPACE/urls.txt" "$WORKSPACE/gau_vivas.txt" | sort -u > "$WORKSPACE/all_urls_final.txt"

if [ -s "$WORKSPACE/all_urls_final.txt" ]; then
    echo -e "${BLUE}[i] Tirando prints dos alvos vivos...${RESET}"
    # Adicionado || true pois gowitness pode falhar em algumas URLs e não queremos parar o script
    gowitness scan file -f "$WORKSPACE/all_urls_final.txt" --screenshot-path "$WORKSPACE/screenshots/" --timeout 10 >/dev/null 2>&1 || true
else
    echo -e "${YELLOW}[!] Nenhuma URL para tirar print.${RESET}"
fi

# ---------------------------------------------------------
# 6. VULNERABILITY SCAN (Nuclei)
# ---------------------------------------------------------
echo -e "\n${GREEN}[6/6] Nuclei (Caçando Vulns)...${RESET}"

touch "$WORKSPACE/nuclei.txt"

# 4️⃣ RATE LIMIT & TIMEOUT NO NUCLEI
if [ -s "$WORKSPACE/urls.txt" ]; then
    nuclei -l "$WORKSPACE/urls.txt" \
           -t http/exposed-panels/ -t http/misconfiguration/ -t http/technologies/ \
           -severity low,medium,high,critical \
           -rl 50 \
           -timeout 5 \
           -o "$WORKSPACE/nuclei.txt" -silent || echo -e "${YELLOW}[!] Nuclei completou com alguns erros.${RESET}"
else
    echo -e "${YELLOW}[!] Pulando Nuclei (sem alvos vivos).${RESET}"
fi

# ---------------------------------------------------------
# RELATÓRIO FINAL
# ---------------------------------------------------------

DURATION=$SECONDS
echo -e "\n${CYAN}=== RESUMO DA OPERAÇÃO ($(($DURATION / 60))m $(($DURATION % 60))s) ===${RESET}"
echo -e "📂 Workspace: $WORKSPACE"
echo -e "📸 Screenshots: $WORKSPACE/screenshots/"
echo -e "🚨 Infra Crítica: $WORKSPACE/infra_exposed.txt $([ -s "$WORKSPACE/infra_exposed.txt" ] && echo "${RED}[VERIFICAR]${RESET}")"
echo -e "💉 Potencial SQLi: $WORKSPACE/params_sqli.txt"

echo -e "🌐 Web Críticos (ScopeSentry):"

if [ -f "$WORKSPACE/alive.json" ]; then
    jq -r 'select(.tags | length > 0) | "   - [\(.tags | join(","))] \(.url)"' "$WORKSPACE/alive.json" 2>/dev/null || true
fi

echo -e "☢️  Vulns Nuclei:"
if [ -s "$WORKSPACE/nuclei.txt" ]; then
    cat "$WORKSPACE/nuclei.txt"
else
    echo "   - Nenhuma vulnerabilidade crítica detectada automaticamente."
fi

echo -e "\n${CYAN}Triagem Finalizada. Boa caçada!${RESET}"
