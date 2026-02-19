#!/usr/bin/env bash

# ==========================================
# TRIAGEMASTER
# Author: Sanmir Gabriel
# Flow: Subfinder -> Naabu -> ScopeSentry -> GAU -> JS Recon -> Nuclei -> GoWitness
# ==========================================

# 1️⃣ BASH STRICT MODE
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

# ------------------------------------------------------------------
# CONFIGURAÇÃO: Caminho do LinkFinder
# Pode ser alias global: export LINKFINDER_BIN="linkfinder"
# Ou caminho direto:     export LINKFINDER_BIN="python3 /opt/LinkFinder/linkfinder.py"
# ------------------------------------------------------------------
LINKFINDER_BIN="${LINKFINDER_BIN:-linkfinder}"

# FIX #4 — Controle de paralelismo para download de JS (padrão: 10 simultâneos)
MAX_PARALLEL_DOWNLOADS="${MAX_PARALLEL_DOWNLOADS:-10}"

RAW_INPUT=${1:-}
DATE=$(date +%Y-%m-%d)
SECONDS=0

# ------------------------------------------------------------------
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

# ------------------------------------------------------------------
# FIX #2 — check_deps sem eval
# Converte LINKFINDER_BIN em array via word-splitting controlado.
# Suporta "python3 /opt/LinkFinder/linkfinder.py" sem eval.
# ------------------------------------------------------------------
check_deps() {
    local tools=("subfinder" "naabu" "scopesentry" "jq" "nuclei" "gau" "uro" "gowitness" "trufflehog")
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo -e "${RED}[X] Erro Critico: '$tool' nao esta instalado ou nao esta no PATH.${RESET}"
            exit 1
        fi
    done

    # Word-splitting intencional para suportar "python3 /path/script.py"
    # shellcheck disable=SC2206
    local lf_cmd=($LINKFINDER_BIN)
    if ! "${lf_cmd[@]}" --help >/dev/null 2>&1; then
        echo -e "${RED}[X] Erro Critico: LinkFinder nao encontrado."
        echo -e "    Configure LINKFINDER_BIN antes de executar."
        echo -e "    Exemplo: export LINKFINDER_BIN='python3 /opt/LinkFinder/linkfinder.py'${RESET}"
        exit 1
    fi
}

# ------------------------------------------------------------------
# FIX #1 — Download com retry e backoff exponencial
# Tenta ate 3 vezes com espera de 2s -> 4s -> 8s entre tentativas.
# Retorna 0 em sucesso, 1 apos esgotar tentativas (sem matar o script).
# ------------------------------------------------------------------
download_with_retry() {
    local url="$1"
    local output="$2"
    local max_attempts=3
    local attempt=1
    local wait_time=2

    while [[ $attempt -le $max_attempts ]]; do
        if curl -sSL \
                --max-time 15 \
                --connect-timeout 8 \
                --retry 0 \
                -o "$output" \
                "$url" 2>/dev/null; then
            if [[ -s "$output" ]]; then
                return 0
            fi
        fi

        echo -e "    ${YELLOW}[~] Retry $attempt/$max_attempts para: $url (aguardando ${wait_time}s)${RESET}" >&2
        sleep "$wait_time"
        wait_time=$(( wait_time * 2 ))
        (( attempt++ ))
    done

    rm -f "$output"
    echo -e "    ${RED}[!] Falha definitiva ao baixar: $url${RESET}" >&2
    return 1
}

# ------------------------------------------------------------------
# FIX #4 — Download paralelo de JS com semaforo de jobs
# Dispara ate MAX_PARALLEL_DOWNLOADS downloads simultaneos.
# ------------------------------------------------------------------
parallel_download_js() {
    local url_file="$1"
    local dest_dir="$2"
    local pids=()

    while IFS= read -r js_url; do
        local local_name
        local_name=$(echo "$js_url" | sed 's|https\?://||; s|[/?=&]|_|g')
        local output_file="$dest_dir/${local_name}.js"

        ( download_with_retry "$js_url" "$output_file" ) &
        pids+=($!)

        # Semaforo: espera o job mais antigo se atingiu o limite
        if [[ ${#pids[@]} -ge $MAX_PARALLEL_DOWNLOADS ]]; then
            wait "${pids[0]}" 2>/dev/null || true
            pids=("${pids[@]:1}")
        fi
    done < "$url_file"

    # Aguarda todos os jobs restantes terminarem
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
}

# ------------------------------------------------------------------
# FIX #5 — Parser de severidades do Nuclei
# Le um arquivo de output do Nuclei e exibe tabela de contagens.
# ------------------------------------------------------------------
print_severity_table() {
    local file="$1"

    if [[ ! -s "$file" ]]; then
        echo -e "   ${BLUE}(sem findings)${RESET}"
        return
    fi

    echo -e "   ${CYAN}+----------------------+-------------------+${RESET}"
    echo -e "   ${CYAN}|  Severidade          |  Findings         |${RESET}"
    echo -e "   ${CYAN}+----------------------+-------------------+${RESET}"

    local has_any=0
    for severity in critical high medium low info; do
        local count
        count=$(grep -ic "\[$severity\]" "$file" 2>/dev/null || echo 0)
        if [[ $count -gt 0 ]]; then
            has_any=1
            local color="$RESET"
            case $severity in
                critical) color="$RED" ;;
                high)     color="$RED" ;;
                medium)   color="$YELLOW" ;;
                low)      color="$BLUE" ;;
                info)     color="$CYAN" ;;
            esac
            printf "   ${CYAN}|${RESET}  %-20s ${color}%-19s${RESET}${CYAN}|${RESET}\n" \
                   "$(echo "$severity" | tr '[:lower:]' '[:upper:]')" "$count"
        fi
    done

    if [[ $has_any -eq 0 ]]; then
        echo -e "   ${BLUE}(nenhum finding com severidade reconhecida)${RESET}"
    fi

    echo -e "   ${CYAN}+----------------------+-------------------+${RESET}"
}

# ------------------------------------------------------------------
# VALIDACAO DE INPUT
# ------------------------------------------------------------------
if [ -z "$RAW_INPUT" ]; then
    banner
    echo "Uso: ./triage.sh <alvo.com>"
    echo "     LINKFINDER_BIN='python3 /opt/LinkFinder/linkfinder.py' ./triage.sh <alvo.com>"
    exit 1
fi

DOMAIN=$(echo "$RAW_INPUT" | sed -E 's|^https?://||I; s|/.*||; s|:.*||')

if ! [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    echo -e "${RED}[X] Input invalido: $DOMAIN${RESET}"
    exit 1
fi

WORKSPACE="recon/${DOMAIN}_${DATE}"

banner
check_deps
mkdir -p "$WORKSPACE"

LOG_FILE="$WORKSPACE/execution.log"
echo -e "${BLUE}[i] Log da execucao sera salvo em: $LOG_FILE${RESET}"
exec > >(tee -a "$LOG_FILE") 2>&1

echo -e "${YELLOW}[*] Iniciando Triagem: $DOMAIN${RESET}"
echo -e "${BLUE}[i] Workspace: $WORKSPACE${RESET}"

# ---------------------------------------------------------
# 1. SUBDOMINIOS
# ---------------------------------------------------------
echo -e "\n${GREEN}[1/6] Subfinder (Enumerando DNS)...${RESET}"

subfinder -d "$DOMAIN" -silent -all > "$WORKSPACE/subs_raw.txt" \
    || { echo -e "${RED}[X] Subfinder falhou!${RESET}"; exit 1; }

if [ -s "$WORKSPACE/subs_raw.txt" ]; then
    sort -u "$WORKSPACE/subs_raw.txt" -o "$WORKSPACE/subs_raw.txt"
    echo -e "    -> Encontrados (Deduplicados): $(wc -l < "$WORKSPACE/subs_raw.txt")"
else
    echo -e "${RED}[!] Nenhum subdominio encontrado. Abortando.${RESET}"
    exit 1
fi

# ---------------------------------------------------------
# 2. PORT SCAN (Infraestrutura)
# ---------------------------------------------------------
echo -e "\n${GREEN}[2/6] Naabu (Portas Criticas Web & Infra)...${RESET}"

naabu -list "$WORKSPACE/subs_raw.txt" \
      -p 21,22,23,25,53,80,110,139,443,445,1433,3306,3389,5432,6379,8000,8080,8443,9000,9200 \
      -silent > "$WORKSPACE/ports.txt" \
      || { echo -e "${RED}[X] Naabu falhou!${RESET}"; exit 1; }

if [ ! -s "$WORKSPACE/ports.txt" ]; then
    echo -e "${RED}[!] Nenhuma porta aberta encontrada.${RESET}"
    exit 1
fi

grep -E ":(21|22|23|25|445|1433|3306|3389|5432|6379)$" "$WORKSPACE/ports.txt" \
    > "$WORKSPACE/infra_exposed.txt" || true

if [ -s "$WORKSPACE/infra_exposed.txt" ]; then
    echo -e "${RED}[!!!] PERIGO: Servicos de Infraestrutura Abertos!${RESET}"
    cat "$WORKSPACE/infra_exposed.txt"
else
    echo -e "${BLUE}[i] Nenhuma infraestrutura critica (SSH/DB) exposta publicamente.${RESET}"
fi

# ---------------------------------------------------------
# 3. VALIDACAO WEB (ScopeSentry)
# ---------------------------------------------------------
echo -e "\n${GREEN}[3/6] ScopeSentry (Validando HTTP/S)...${RESET}"

scopesentry -c 100 -t 3 -L -json < "$WORKSPACE/ports.txt" > "$WORKSPACE/alive.json" \
    || { echo -e "${RED}[X] ScopeSentry falhou!${RESET}"; exit 1; }

if jq empty "$WORKSPACE/alive.json" >/dev/null 2>&1; then
    jq -r .url "$WORKSPACE/alive.json" > "$WORKSPACE/urls.txt"
else
    echo -e "${RED}[X] Erro: JSON invalido gerado pelo ScopeSentry.${RESET}"
    touch "$WORKSPACE/urls.txt"
fi

COUNT_ALIVE=$(wc -l < "$WORKSPACE/urls.txt")
echo -e "    -> Web Services Vivos: $COUNT_ALIVE"

# ---------------------------------------------------------
# 4. MINERACAO HISTORICA (GAU + URO) + JS RECON
# ---------------------------------------------------------
echo -e "\n${GREEN}[4/6] GAU (Minerando URLs Antigas)...${RESET}"
echo -e "${BLUE}[i] Baixando e Limpando com URO...${RESET}"

gau "$DOMAIN" --subs --threads 5 | uro > "$WORKSPACE/gau_clean.txt" \
    || echo -e "${YELLOW}[!] GAU retornou erro, verificando output parcial...${RESET}"

touch "$WORKSPACE/gau_vivas.txt" "$WORKSPACE/params_sqli.txt"

if [ -s "$WORKSPACE/gau_clean.txt" ]; then
    echo -e "${BLUE}[i] Validando existencia com ScopeSentry...${RESET}"

    scopesentry -c 50 -t 5 -mc 200,301,302,403,500 -json \
        < "$WORKSPACE/gau_clean.txt" > "$WORKSPACE/gau_alive.json" || true

    if [ -s "$WORKSPACE/gau_alive.json" ] && jq empty "$WORKSPACE/gau_alive.json" >/dev/null 2>&1; then
        jq -r .url "$WORKSPACE/gau_alive.json" > "$WORKSPACE/gau_vivas.txt"
        echo -e "    -> URLs Historicas Vivas: $(wc -l < "$WORKSPACE/gau_vivas.txt")"

        echo -e "${BLUE}[i] Buscando parametros suspeitos...${RESET}"
        grep -E '\?.+=' "$WORKSPACE/gau_vivas.txt" > "$WORKSPACE/params_sqli.txt" || true
    fi
else
    echo -e "${YELLOW}[!] GAU nao encontrou URLs ou falhou.${RESET}"
fi

# ------------------------------------------------------------------
# 4.1 JS RECON
# ------------------------------------------------------------------
echo -e "\n${CYAN}[4.1] JS Recon (Extraindo, Baixando e Analisando .js)...${RESET}"

JS_DIR="$WORKSPACE/js_files"
mkdir -p "$JS_DIR"

grep -E '\.js(\?|$)' "$WORKSPACE/gau_clean.txt" "$WORKSPACE/urls.txt" 2>/dev/null \
    | sort -u > "$WORKSPACE/js_raw.txt" || true

touch "$WORKSPACE/js_alive.txt"

if [ -s "$WORKSPACE/js_raw.txt" ]; then
    echo -e "    -> .js encontrados no historico: $(wc -l < "$WORKSPACE/js_raw.txt")"

    echo -e "${BLUE}[i] Validando JS vivos (HTTP 200)...${RESET}"
    scopesentry -c 50 -t 5 -mc 200 -json < "$WORKSPACE/js_raw.txt" \
        > "$WORKSPACE/js_alive.json" || true

    if [ -s "$WORKSPACE/js_alive.json" ] && jq empty "$WORKSPACE/js_alive.json" >/dev/null 2>&1; then
        jq -r .url "$WORKSPACE/js_alive.json" > "$WORKSPACE/js_alive.txt"
        echo -e "    -> .js vivos (online): $(wc -l < "$WORKSPACE/js_alive.txt")"
    fi
else
    echo -e "${YELLOW}[!] Nenhum .js encontrado.${RESET}"
fi

touch "$WORKSPACE/js_endpoints.txt" \
      "$WORKSPACE/trufflehog_verified.json" \
      "$WORKSPACE/trufflehog_all.json"

if [ -s "$WORKSPACE/js_alive.txt" ]; then

    # FIX #4 — Download paralelo com semaforo
    # FIX #1 — Cada download usa retry + backoff exponencial
    echo -e "${BLUE}[i] Baixando JS vivos em paralelo (max ${MAX_PARALLEL_DOWNLOADS} simultaneos, retry 3x)...${RESET}"
    parallel_download_js "$WORKSPACE/js_alive.txt" "$JS_DIR"

    JS_DOWNLOADED=$(find "$JS_DIR" -name "*.js" -size +0c 2>/dev/null | wc -l)
    echo -e "    -> JS baixados com sucesso: $JS_DOWNLOADED / $(wc -l < "$WORKSPACE/js_alive.txt")"

    # FIX #2 — Sem eval: usa array seguro
    # shellcheck disable=SC2206
    LF_CMD=($LINKFINDER_BIN)

    echo -e "${BLUE}[i] Rodando LinkFinder nos JS baixados...${RESET}"
    for js_file in "$JS_DIR"/*.js; do
        [ -f "$js_file" ] || continue
        "${LF_CMD[@]}" -i "$js_file" -o cli >> "$WORKSPACE/js_endpoints.txt" 2>/dev/null || true
    done

    sort -u "$WORKSPACE/js_endpoints.txt" -o "$WORKSPACE/js_endpoints.txt"
    echo -e "    -> Endpoints extraidos via LinkFinder: $(wc -l < "$WORKSPACE/js_endpoints.txt")"

    # FIX #3 — TruffleHog em dois modos separados
    echo -e "${BLUE}[i] TruffleHog VERIFIED (baixo ruido — segredos confirmados)...${RESET}"
    trufflehog filesystem "$JS_DIR" \
        --no-update \
        --only-verified \
        --json > "$WORKSPACE/trufflehog_verified.json" 2>/dev/null || true

    echo -e "${BLUE}[i] TruffleHog ALL (cobertura maxima — inclui nao verificados)...${RESET}"
    trufflehog filesystem "$JS_DIR" \
        --no-update \
        --json > "$WORKSPACE/trufflehog_all.json" 2>/dev/null || true

    SECRETS_VERIFIED=$(grep -c '"DetectorName"' "$WORKSPACE/trufflehog_verified.json" 2>/dev/null || echo 0)
    SECRETS_ALL=$(grep -c '"DetectorName"' "$WORKSPACE/trufflehog_all.json" 2>/dev/null || echo 0)
    SECRETS_UNVERIFIED=$(( SECRETS_ALL - SECRETS_VERIFIED ))

    if [[ $SECRETS_VERIFIED -gt 0 ]]; then
        echo -e "${RED}[!!!] TruffleHog VERIFIED: $SECRETS_VERIFIED segredo(s) confirmado(s)! -> trufflehog_verified.json${RESET}"
    else
        echo -e "${BLUE}[i] TruffleHog VERIFIED: nenhum segredo confirmado.${RESET}"
    fi
    if [[ $SECRETS_UNVERIFIED -gt 0 ]]; then
        echo -e "${YELLOW}[~] TruffleHog UNVERIFIED: $SECRETS_UNVERIFIED candidato(s) para revisao manual -> trufflehog_all.json${RESET}"
    fi

else
    echo -e "${YELLOW}[!] Nenhum JS vivo para baixar/analisar.${RESET}"
fi

# ---------------------------------------------------------
# 5. VISUAL RECON (Screenshots)
# ---------------------------------------------------------
echo -e "\n${GREEN}[5/6] GoWitness (Tirando Prints)...${RESET}"

cat "$WORKSPACE/urls.txt" "$WORKSPACE/gau_vivas.txt" | sort -u \
    > "$WORKSPACE/all_urls_final.txt"

if [ -s "$WORKSPACE/all_urls_final.txt" ]; then
    echo -e "${BLUE}[i] Tirando prints dos alvos vivos...${RESET}"
    gowitness scan file \
        -f "$WORKSPACE/all_urls_final.txt" \
        --screenshot-path "$WORKSPACE/screenshots/" \
        --timeout 10 >/dev/null 2>&1 || true
else
    echo -e "${YELLOW}[!] Nenhuma URL para tirar print.${RESET}"
fi

# ---------------------------------------------------------
# 6. VULNERABILITY SCAN (Nuclei)
# ---------------------------------------------------------
echo -e "\n${GREEN}[6/6] Nuclei (Cacando Vulns)...${RESET}"

touch "$WORKSPACE/nuclei.txt" "$WORKSPACE/nuclei_js_secrets.txt"

# --- 6.1: Scan principal ---
if [ -s "$WORKSPACE/urls.txt" ]; then
    echo -e "${BLUE}[i] Scan principal: paineis, misconfiguracoes e tecnologias...${RESET}"
    nuclei -l "$WORKSPACE/urls.txt" \
           -t http/exposed-panels/ \
           -t http/misconfiguration/ \
           -t http/technologies/ \
           -severity low,medium,high,critical \
           -rl 50 \
           -timeout 5 \
           -o "$WORKSPACE/nuclei.txt" -silent \
           || echo -e "${YELLOW}[!] Nuclei completou com alguns erros.${RESET}"
else
    echo -e "${YELLOW}[!] Pulando Nuclei scan principal (sem alvos vivos).${RESET}"
fi

# --- 6.2: Scan de segredos nas URLs GAU + JS vivos ---
cat "$WORKSPACE/gau_vivas.txt" "$WORKSPACE/js_alive.txt" 2>/dev/null \
    | sort -u > "$WORKSPACE/nuclei_secrets_targets.txt" || true

if [ -s "$WORKSPACE/nuclei_secrets_targets.txt" ]; then
    echo -e "${BLUE}[i] Scan de segredos/tokens (GAU + JS vivos)...${RESET}"
    nuclei -l "$WORKSPACE/nuclei_secrets_targets.txt" \
           -t http/exposures/ \
           -tags token,secret,api-key,exposure,leak \
           -severity low,medium,high,critical \
           -rl 30 \
           -timeout 5 \
           -o "$WORKSPACE/nuclei_js_secrets.txt" -silent \
           || echo -e "${YELLOW}[!] Nuclei (secrets) completou com alguns erros.${RESET}"
else
    echo -e "${YELLOW}[!] Pulando scan de segredos (sem alvos GAU/JS).${RESET}"
fi

# ---------------------------------------------------------
# RELATORIO FINAL
# ---------------------------------------------------------

DURATION=$SECONDS
echo -e "\n${CYAN}+======================================================+${RESET}"
printf "${CYAN}|  RESUMO DA OPERACAO — %02dm %02ds%-24s|${RESET}\n" \
    "$(( DURATION / 60 ))" "$(( DURATION % 60 ))" " "
echo -e "${CYAN}+======================================================+${RESET}"

echo -e "\n${CYAN}-- Artefatos Gerados --------------------------------${RESET}"
echo -e "  Workspace        : $WORKSPACE"
echo -e "  Screenshots      : $WORKSPACE/screenshots/"
printf "  JS Endpoints     : %s (%s endpoints)\n" \
    "$WORKSPACE/js_endpoints.txt" "$(wc -l < "$WORKSPACE/js_endpoints.txt")"
printf "  Params (SQLi)    : %s (%s params)\n" \
    "$WORKSPACE/params_sqli.txt" "$(wc -l < "$WORKSPACE/params_sqli.txt")"

if [ -s "$WORKSPACE/infra_exposed.txt" ]; then
    echo -e "  ${RED}[!!!] Infra Exposta: $WORKSPACE/infra_exposed.txt ($(wc -l < "$WORKSPACE/infra_exposed.txt") hosts)${RESET}"
else
    echo -e "  Infra Exposta    : (limpa)"
fi

if [ -s "$WORKSPACE/trufflehog_verified.json" ]; then
    VERIFIED_COUNT=$(grep -c '"DetectorName"' "$WORKSPACE/trufflehog_verified.json" 2>/dev/null || echo 0)
    echo -e "  ${RED}[!!!] Secrets OK  : $WORKSPACE/trufflehog_verified.json ($VERIFIED_COUNT confirmados)${RESET}"
else
    echo -e "  Secrets VERIFIED : (nenhum confirmado)"
fi

ALL_COUNT=$(grep -c '"DetectorName"' "$WORKSPACE/trufflehog_all.json" 2>/dev/null || echo 0)
echo -e "  ${YELLOW}Secrets ALL      : $WORKSPACE/trufflehog_all.json ($ALL_COUNT total — inclui nao verificados)${RESET}"

echo -e "\n${CYAN}-- Nuclei: Scan Principal ---------------------------${RESET}"
print_severity_table "$WORKSPACE/nuclei.txt"

echo -e "\n${CYAN}-- Nuclei: Secrets / Exposures (GAU + JS) ----------${RESET}"
print_severity_table "$WORKSPACE/nuclei_js_secrets.txt"

echo -e "\n${CYAN}-- Web Services com Tags (ScopeSentry) --------------${RESET}"
if [ -f "$WORKSPACE/alive.json" ]; then
    jq -r 'select(.tags | length > 0) | "  [\(.tags | join(","))] \(.url)"' \
        "$WORKSPACE/alive.json" 2>/dev/null || true
else
    echo -e "  (sem dados)"
fi

echo -e "\n${CYAN}Triagem Finalizada. Boa cacada!${RESET}\n"
