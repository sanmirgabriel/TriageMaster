#!/usr/bin/env bash

# ==========================================
# TRIAGEMASTER 
# Author: Sanmir Gabriel
# Flow:
#   Subfinder -> dnsx (resolve) -> dnsx (takeover CNAME) -> Naabu
#   -> ScopeSentry -> wafw00f -> GAU -> JS Recon -> Arjun
#   -> Nuclei (panels + misconfig + CVEs + secrets) -> GoWitness
# ==========================================

set -euo pipefail

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
RESET='\033[0m'

trap 'echo -e "\n${RED}[!] Execucao interrompida (SIGINT). Saindo...${RESET}"; exit 1' INT

# ------------------------------------------------------------------
# CONFIGURACAO
# ------------------------------------------------------------------

# LinkFinder: alias global ou caminho absoluto
# export LINKFINDER_BIN="python3 /opt/LinkFinder/linkfinder.py"
LINKFINDER_BIN="${LINKFINDER_BIN:-linkfinder}"

# Paralelismo no download de JS
MAX_PARALLEL_DOWNLOADS="${MAX_PARALLEL_DOWNLOADS:-10}"

# Arjun: wordlist customizada opcional
# export ARJUN_WORDLIST="/opt/wordlists/params.txt"
ARJUN_WORDLIST="${ARJUN_WORDLIST:-}"

# wafw00f: limite de URLs para rodar (evitar timeout em alvos grandes)
WAF_LIMIT="${WAF_LIMIT:-50}"

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
# check_deps 
# ------------------------------------------------------------------
check_deps() {
    # Ferramentas obrigatórias
    local tools=(
        "subfinder" "dnsx" "naabu" "scopesentry"
        "jq" "nuclei" "gau" "uro" "gowitness"
        "trufflehog" "arjun" "wafw00f"
    )
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo -e "${RED}[X] Erro Critico: '$tool' nao esta instalado ou nao esta no PATH.${RESET}"
            exit 1
        fi
    done

    # subzy é opcional — usamos nuclei takeovers como fallback
    SUBZY_AVAILABLE=0
    if command -v "subzy" >/dev/null 2>&1; then
        SUBZY_AVAILABLE=1
        echo -e "${BLUE}[i] subzy detectado — sera usado em conjunto com nuclei takeovers.${RESET}"
    else
        echo -e "${YELLOW}[~] subzy nao encontrado — takeover check sera feito apenas via nuclei.${RESET}"
    fi

    # LinkFinder: word-splitting intencional, sem eval
    # shellcheck disable=SC2206
    local lf_cmd=($LINKFINDER_BIN)
    if ! "${lf_cmd[@]}" --help >/dev/null 2>&1; then
        echo -e "${RED}[X] Erro Critico: LinkFinder nao encontrado."
        echo -e "    Configure: export LINKFINDER_BIN='python3 /opt/LinkFinder/linkfinder.py'${RESET}"
        exit 1
    fi
}

download_with_retry() {
    local url="$1"
    local output="$2"
    local max_attempts=3
    local attempt=1
    local wait_time=2

    while [[ $attempt -le $max_attempts ]]; do
        if curl -sSL --max-time 15 --connect-timeout 8 --retry 0 \
                -o "$output" "$url" 2>/dev/null; then
            [[ -s "$output" ]] && return 0
        fi
        echo -e "    ${YELLOW}[~] Retry $attempt/$max_attempts: $url (${wait_time}s)${RESET}" >&2
        sleep "$wait_time"
        wait_time=$(( wait_time * 2 ))
        (( attempt++ ))
    done

    rm -f "$output"
    echo -e "    ${RED}[!] Falha definitiva: $url${RESET}" >&2
    return 1
}

# ------------------------------------------------------------------
# parallel_download_js — semáforo de jobs
# ------------------------------------------------------------------
parallel_download_js() {
    local url_file="$1"
    local dest_dir="$2"
    local pids=()

    while IFS= read -r js_url; do
        local local_name
        local_name=$(echo "$js_url" | sed 's|https\?://||; s|[/?=&]|_|g')
        ( download_with_retry "$js_url" "$dest_dir/${local_name}.js" ) &
        pids+=($!)

        if [[ ${#pids[@]} -ge $MAX_PARALLEL_DOWNLOADS ]]; then
            wait "${pids[0]}" 2>/dev/null || true
            pids=("${pids[@]:1}")
        fi
    done < "$url_file"

    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
}

# ------------------------------------------------------------------
# print_severity_table — tabela de findings por severidade
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
                critical|high) color="$RED"     ;;
                medium)        color="$YELLOW"  ;;
                low)           color="$BLUE"    ;;
                info)          color="$CYAN"    ;;
            esac
            printf "   ${CYAN}|${RESET}  %-20s ${color}%-19s${RESET}${CYAN}|${RESET}\n" \
                   "$(echo "$severity" | tr '[:lower:]' '[:upper:]')" "$count"
        fi
    done

    [[ $has_any -eq 0 ]] && echo -e "   ${BLUE}(nenhum finding com severidade reconhecida)${RESET}"
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
echo -e "${BLUE}[i] Log: $LOG_FILE${RESET}"
exec > >(tee -a "$LOG_FILE") 2>&1

echo -e "${YELLOW}[*] Iniciando Triagem: $DOMAIN${RESET}"
echo -e "${BLUE}[i] Workspace: $WORKSPACE${RESET}"

# ==========================================================
# FASE 1 — SUBDOMINIOS (Subfinder)
# ==========================================================
echo -e "\n${GREEN}[1/8] Subfinder (Enumerando DNS)...${RESET}"

subfinder -d "$DOMAIN" -silent -all > "$WORKSPACE/subs_raw.txt" \
    || { echo -e "${RED}[X] Subfinder falhou!${RESET}"; exit 1; }

if [ -s "$WORKSPACE/subs_raw.txt" ]; then
    sort -u "$WORKSPACE/subs_raw.txt" -o "$WORKSPACE/subs_raw.txt"
    echo -e "    -> Subdominios brutos (deduplicados): $(wc -l < "$WORKSPACE/subs_raw.txt")"
else
    echo -e "${RED}[!] Nenhum subdominio encontrado. Abortando.${RESET}"
    exit 1
fi

# ==========================================================
# FASE 2 — DNS RESOLUTION + SUBDOMAIN TAKEOVER
# ==========================================================
echo -e "\n${GREEN}[2/8] dnsx (DNS Resolution + CNAME Takeover Check)...${RESET}"

# 2.1 — Filtra subdominios que resolvem (A/AAAA/CNAME ativo)
# -resp: mostra o IP resolvido no output para debug
# -silent: sem banner
dnsx -l "$WORKSPACE/subs_raw.txt" \
     -silent \
     -resp \
     > "$WORKSPACE/subs_resolved_raw.txt" || true

if [ ! -s "$WORKSPACE/subs_resolved_raw.txt" ]; then
    echo -e "${RED}[!] Nenhum subdominio com DNS ativo. Abortando.${RESET}"
    exit 1
fi

# Extrai apenas os hostnames (primeira coluna) para uso no Naabu
awk '{print $1}' "$WORKSPACE/subs_resolved_raw.txt" \
    > "$WORKSPACE/subs_resolved.txt"

RESOLVED_COUNT=$(wc -l < "$WORKSPACE/subs_resolved.txt")
DEAD_COUNT=$(( $(wc -l < "$WORKSPACE/subs_raw.txt") - RESOLVED_COUNT ))
echo -e "    -> Com DNS ativo  : $RESOLVED_COUNT"
echo -e "    -> Mortos (filtrados do Naabu): $DEAD_COUNT"

# 2.2 — CNAME Takeover: extrai CNAMEs da resolucao
echo -e "${BLUE}[i] Extraindo cadeia CNAME para takeover check...${RESET}"

dnsx -l "$WORKSPACE/subs_resolved.txt" \
     -silent \
     -cname \
     -cdn \
     > "$WORKSPACE/cnames.txt" 2>/dev/null || true

touch "$WORKSPACE/takeover_candidates.txt" "$WORKSPACE/takeover_nuclei.txt"

if [ -s "$WORKSPACE/cnames.txt" ]; then
    # Subdominios com CNAME mas sem CDN = candidatos a takeover
    awk '{print $1}' "$WORKSPACE/cnames.txt" \
        > "$WORKSPACE/takeover_candidates.txt"
    echo -e "    -> Candidatos a takeover (CNAME sem CDN): $(wc -l < "$WORKSPACE/takeover_candidates.txt")"
    
    echo -e "${BLUE}[i] Nuclei: verificando subdomain takeover...${RESET}"
    nuclei -l "$WORKSPACE/takeover_candidates.txt" \
           -t http/takeovers/ \
           -silent \
           -rl 30 \
           -timeout 8 \
           -o "$WORKSPACE/takeover_nuclei.txt" || true

    # subzy complementa o nuclei (fingerprints diferentes)
    if [[ $SUBZY_AVAILABLE -eq 1 ]]; then
        echo -e "${BLUE}[i] subzy: segundo check de takeover...${RESET}"
        subzy run \
            --targets "$WORKSPACE/takeover_candidates.txt" \
            --hide-fails \
            >> "$WORKSPACE/takeover_nuclei.txt" 2>/dev/null || true
    fi

    if [ -s "$WORKSPACE/takeover_nuclei.txt" ]; then
        echo -e "${RED}[!!!] SUBDOMAIN TAKEOVER DETECTADO!${RESET}"
        cat "$WORKSPACE/takeover_nuclei.txt"
    else
        echo -e "${BLUE}[i] Nenhum takeover confirmado.${RESET}"
    fi
else
    echo -e "${BLUE}[i] Nenhum CNAME elegivel para takeover encontrado.${RESET}"
fi

# ==========================================================
# FASE 3 — PORT SCAN (Naabu com subs_resolved)
# ==========================================================
echo -e "\n${GREEN}[3/8] Naabu (Portas Criticas — apenas hosts com DNS ativo)...${RESET}"

naabu -list "$WORKSPACE/subs_resolved.txt" \
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
    echo -e "${BLUE}[i] Nenhuma infraestrutura critica exposta.${RESET}"
fi

# ==========================================================
# FASE 4 — VALIDACAO WEB (ScopeSentry)
# ==========================================================
echo -e "\n${GREEN}[4/8] ScopeSentry (Validando HTTP/S)...${RESET}"

scopesentry -c 100 -t 3 -L -json < "$WORKSPACE/ports.txt" \
    > "$WORKSPACE/alive.json" \
    || { echo -e "${RED}[X] ScopeSentry falhou!${RESET}"; exit 1; }

if jq empty "$WORKSPACE/alive.json" >/dev/null 2>&1; then
    jq -r .url "$WORKSPACE/alive.json" > "$WORKSPACE/urls.txt"
else
    echo -e "${RED}[X] JSON invalido do ScopeSentry.${RESET}"
    touch "$WORKSPACE/urls.txt"
fi

echo -e "    -> Web Services Vivos: $(wc -l < "$WORKSPACE/urls.txt")"

# ==========================================================
# FASE 5 — WAF DETECTION (wafw00f)
# ==========================================================
echo -e "\n${GREEN}[5/8] wafw00f (WAF Detection)...${RESET}"

touch "$WORKSPACE/waf_results.txt"

if [ -s "$WORKSPACE/urls.txt" ]; then
    # Pega as primeiras WAF_LIMIT URLs para nao travar o pipeline
    head -n "$WAF_LIMIT" "$WORKSPACE/urls.txt" > "$WORKSPACE/waf_targets.txt"
    echo -e "${BLUE}[i] Verificando WAF em $(wc -l < "$WORKSPACE/waf_targets.txt") URLs (limite: $WAF_LIMIT)...${RESET}"

    while IFS= read -r target_url; do
        wafw00f "$target_url" -o - 2>/dev/null >> "$WORKSPACE/waf_results.txt" || true
    done < "$WORKSPACE/waf_targets.txt"

    # Extrai hosts com WAF detectado (linhas com "is behind")
    WAF_DETECTED=$(grep -c "is behind" "$WORKSPACE/waf_results.txt" 2>/dev/null || echo 0)
    WAF_NONE=$(grep -c "No WAF detected" "$WORKSPACE/waf_results.txt" 2>/dev/null || echo 0)

    if [[ $WAF_DETECTED -gt 0 ]]; then
        echo -e "    ${YELLOW}-> WAF Detectado em: $WAF_DETECTED host(s) — ajuste o rate limit do Nuclei${RESET}"
        grep "is behind" "$WORKSPACE/waf_results.txt" | sed 's/^/    /'
    else
        echo -e "    ${BLUE}-> Sem WAF detectado ($WAF_NONE verificados)${RESET}"
    fi
else
    echo -e "${YELLOW}[!] Sem URLs para verificar WAF.${RESET}"
fi

# Define rate limit do Nuclei baseado na presenca de WAF
# Se WAF encontrado: conservador (15 req/s). Sem WAF: agressivo (50 req/s).
if [[ ${WAF_DETECTED:-0} -gt 0 ]]; then
    NUCLEI_RL=15
    echo -e "    ${YELLOW}[i] Nuclei rodara com -rl $NUCLEI_RL (WAF detectado).${RESET}"
else
    NUCLEI_RL=50
    echo -e "    ${BLUE}[i] Nuclei rodara com -rl $NUCLEI_RL (sem WAF).${RESET}"
fi

# ==========================================================
# FASE 6 — MINERACAO HISTORICA (GAU + URO) + JS RECON + ARJUN
# ==========================================================
echo -e "\n${GREEN}[6/8] GAU (Minerando URLs Antigas) + JS Recon + Arjun...${RESET}"

gau "$DOMAIN" --subs --threads 5 | uro > "$WORKSPACE/gau_clean.txt" \
    || echo -e "${YELLOW}[!] GAU retornou erro, verificando output parcial...${RESET}"

touch "$WORKSPACE/gau_vivas.txt" \
      "$WORKSPACE/params_sqli.txt" \
      "$WORKSPACE/params_arjun.txt"

if [ -s "$WORKSPACE/gau_clean.txt" ]; then
    echo -e "${BLUE}[i] Validando URLs com ScopeSentry...${RESET}"

    scopesentry -c 50 -t 5 -mc 200,301,302,403,500 -json \
        < "$WORKSPACE/gau_clean.txt" > "$WORKSPACE/gau_alive.json" || true

    if [ -s "$WORKSPACE/gau_alive.json" ] && jq empty "$WORKSPACE/gau_alive.json" >/dev/null 2>&1; then
        jq -r .url "$WORKSPACE/gau_alive.json" > "$WORKSPACE/gau_vivas.txt"
        echo -e "    -> URLs Historicas Vivas: $(wc -l < "$WORKSPACE/gau_vivas.txt")"

        grep -E '\?.+=' "$WORKSPACE/gau_vivas.txt" > "$WORKSPACE/params_sqli.txt" || true
        echo -e "    -> Params historicos (SQLi/XSS): $(wc -l < "$WORKSPACE/params_sqli.txt")"
    fi
else
    echo -e "${YELLOW}[!] GAU nao encontrou URLs ou falhou.${RESET}"
fi

# ------------------------------------------------------------------
# 6.1 — ARJUN: bruteforce de parametros nas URLs vivas
# ------------------------------------------------------------------
echo -e "\n${CYAN}[6.1] Arjun (Bruteforce de Parametros)...${RESET}"

if [ -s "$WORKSPACE/urls.txt" ]; then
    grep -v '?' "$WORKSPACE/urls.txt" > "$WORKSPACE/arjun_targets.txt" || true

    if [ -s "$WORKSPACE/arjun_targets.txt" ]; then
        ARJUN_TARGET_COUNT=$(wc -l < "$WORKSPACE/arjun_targets.txt")
        echo -e "    -> Alvos para Arjun (sem params): $ARJUN_TARGET_COUNT"

        ARJUN_EXTRA_ARGS=""
        if [ -n "$ARJUN_WORDLIST" ] && [ -f "$ARJUN_WORDLIST" ]; then
            ARJUN_EXTRA_ARGS="-w $ARJUN_WORDLIST"
            echo -e "    -> Wordlist customizada: $ARJUN_WORDLIST"
        fi

        arjun \
            -i "$WORKSPACE/arjun_targets.txt" \
            -t 5 \
            --stable \
            -oT "$WORKSPACE/params_arjun.txt" \
            $ARJUN_EXTRA_ARGS \
            2>/dev/null || echo -e "${YELLOW}[!] Arjun completou com alguns erros.${RESET}"

        if [ -s "$WORKSPACE/params_arjun.txt" ]; then
            echo -e "    ${CYAN}-> Arjun encontrou: $(wc -l < "$WORKSPACE/params_arjun.txt") URLs com parametros novos${RESET}"
        else
            echo -e "    ${BLUE}[i] Arjun: nenhum parametro novo descoberto.${RESET}"
        fi
    else
        echo -e "${YELLOW}[!] Todas as URLs ja tem parametros. Pulando Arjun.${RESET}"
    fi
else
    echo -e "${YELLOW}[!] Sem URLs vivas para Arjun.${RESET}"
fi

# ------------------------------------------------------------------
# 6.2 — JS RECON
# ------------------------------------------------------------------
echo -e "\n${CYAN}[6.2] JS Recon (Extraindo, Baixando e Analisando .js)...${RESET}"

JS_DIR="$WORKSPACE/js_files"
mkdir -p "$JS_DIR"

grep -E '\.js(\?|$)' "$WORKSPACE/gau_clean.txt" "$WORKSPACE/urls.txt" 2>/dev/null \
    | sort -u > "$WORKSPACE/js_raw.txt" || true

touch "$WORKSPACE/js_alive.txt" \
      "$WORKSPACE/js_endpoints.txt" \
      "$WORKSPACE/trufflehog_verified.json" \
      "$WORKSPACE/trufflehog_all.json"

if [ -s "$WORKSPACE/js_raw.txt" ]; then
    echo -e "    -> .js no historico: $(wc -l < "$WORKSPACE/js_raw.txt")"

    scopesentry -c 50 -t 5 -mc 200 -json < "$WORKSPACE/js_raw.txt" \
        > "$WORKSPACE/js_alive.json" || true

    if [ -s "$WORKSPACE/js_alive.json" ] && jq empty "$WORKSPACE/js_alive.json" >/dev/null 2>&1; then
        jq -r .url "$WORKSPACE/js_alive.json" > "$WORKSPACE/js_alive.txt"
        echo -e "    -> .js vivos: $(wc -l < "$WORKSPACE/js_alive.txt")"
    fi
else
    echo -e "${YELLOW}[!] Nenhum .js encontrado.${RESET}"
fi

if [ -s "$WORKSPACE/js_alive.txt" ]; then
    echo -e "${BLUE}[i] Download paralelo (max $MAX_PARALLEL_DOWNLOADS, retry 3x + backoff)...${RESET}"
    parallel_download_js "$WORKSPACE/js_alive.txt" "$JS_DIR"

    JS_DOWNLOADED=$(find "$JS_DIR" -name "*.js" -size +0c 2>/dev/null | wc -l)
    echo -e "    -> JS baixados: $JS_DOWNLOADED / $(wc -l < "$WORKSPACE/js_alive.txt")"

    # shellcheck disable=SC2206
    LF_CMD=($LINKFINDER_BIN)
    echo -e "${BLUE}[i] LinkFinder extraindo endpoints...${RESET}"
    for js_file in "$JS_DIR"/*.js; do
        [ -f "$js_file" ] || continue
        "${LF_CMD[@]}" -i "$js_file" -o cli >> "$WORKSPACE/js_endpoints.txt" 2>/dev/null || true
    done
    sort -u "$WORKSPACE/js_endpoints.txt" -o "$WORKSPACE/js_endpoints.txt"
    echo -e "    -> Endpoints extraidos: $(wc -l < "$WORKSPACE/js_endpoints.txt")"

    echo -e "${BLUE}[i] TruffleHog VERIFIED...${RESET}"
    trufflehog filesystem "$JS_DIR" --no-update --only-verified \
        --json > "$WORKSPACE/trufflehog_verified.json" 2>/dev/null || true

    echo -e "${BLUE}[i] TruffleHog ALL (cobertura maxima)...${RESET}"
    trufflehog filesystem "$JS_DIR" --no-update \
        --json > "$WORKSPACE/trufflehog_all.json" 2>/dev/null || true

    SECRETS_V=$(grep -c '"DetectorName"' "$WORKSPACE/trufflehog_verified.json" 2>/dev/null || echo 0)
    SECRETS_A=$(grep -c '"DetectorName"' "$WORKSPACE/trufflehog_all.json" 2>/dev/null || echo 0)

    [[ $SECRETS_V -gt 0 ]] && \
        echo -e "${RED}[!!!] TruffleHog VERIFIED: $SECRETS_V confirmado(s)! -> trufflehog_verified.json${RESET}"
    [[ $(( SECRETS_A - SECRETS_V )) -gt 0 ]] && \
        echo -e "${YELLOW}[~] TruffleHog UNVERIFIED: $(( SECRETS_A - SECRETS_V )) candidato(s) -> trufflehog_all.json${RESET}"
else
    echo -e "${YELLOW}[!] Nenhum JS vivo para analisar.${RESET}"
fi

# ==========================================================
# FASE 7 — VISUAL RECON (GoWitness)
# ==========================================================
echo -e "\n${GREEN}[7/8] GoWitness (Screenshots)...${RESET}"

cat "$WORKSPACE/urls.txt" "$WORKSPACE/gau_vivas.txt" | sort -u \
    > "$WORKSPACE/all_urls_final.txt"

if [ -s "$WORKSPACE/all_urls_final.txt" ]; then
    gowitness scan file \
        -f "$WORKSPACE/all_urls_final.txt" \
        --screenshot-path "$WORKSPACE/screenshots/" \
        --timeout 10 >/dev/null 2>&1 || true
    echo -e "    -> Prints tirados em: $WORKSPACE/screenshots/"
else
    echo -e "${YELLOW}[!] Nenhuma URL para screenshot.${RESET}"
fi

# ==========================================================
# FASE 8 — VULNERABILITY SCAN (Nuclei)
#
# Tres scans separados:
# 8.1 — Paineis/misconfig/tecnologias (inventario e superficie)
# 8.2 — CVEs high/critical (vulnerabilidades reais exploraveis)
# 8.3 — Secrets/tokens em URLs GAU + JS (vazamentos de dados)
# ==========================================================
echo -e "\n${GREEN}[8/8] Nuclei (Inventario + CVEs + Secrets)...${RESET}"

touch "$WORKSPACE/nuclei_inventory.txt" \
      "$WORKSPACE/nuclei_cves.txt" \
      "$WORKSPACE/nuclei_secrets.txt"

# --- 8.1: Inventario (paineis, misconfig, tecnologias) ---
if [ -s "$WORKSPACE/urls.txt" ]; then
    echo -e "${BLUE}[i] 8.1 Inventario: paineis, misconfiguracoes, tecnologias (-rl $NUCLEI_RL)...${RESET}"
    nuclei -l "$WORKSPACE/urls.txt" \
           -t http/exposed-panels/ \
           -t http/misconfiguration/ \
           -t http/technologies/ \
           -severity low,medium,high,critical \
           -rl "$NUCLEI_RL" \
           -timeout 5 \
           -o "$WORKSPACE/nuclei_inventory.txt" -silent \
           || echo -e "${YELLOW}[!] Nuclei inventario completou com erros.${RESET}"
else
    echo -e "${YELLOW}[!] Sem alvos para inventario Nuclei.${RESET}"
fi

# --- 8.2: CVEs high/critical ---
#
# Rodamos APENAS high e critical para manter o foco:
if [ -s "$WORKSPACE/urls.txt" ]; then
    CVE_RL=$(( NUCLEI_RL / 2 ))
    echo -e "${BLUE}[i] 8.2 CVEs: high e critical (-rl $CVE_RL)...${RESET}"
    nuclei -l "$WORKSPACE/urls.txt" \
           -t http/cves/ \
           -severity high,critical \
           -rl "$CVE_RL" \
           -timeout 8 \
           -o "$WORKSPACE/nuclei_cves.txt" -silent \
           || echo -e "${YELLOW}[!] Nuclei CVEs completou com erros.${RESET}"

    if [ -s "$WORKSPACE/nuclei_cves.txt" ]; then
        CVE_COUNT=$(wc -l < "$WORKSPACE/nuclei_cves.txt")
        echo -e "${RED}[!!!] $CVE_COUNT CVE(s) high/critical encontrado(s)! -> nuclei_cves.txt${RESET}"
    else
        echo -e "${BLUE}[i] Nenhum CVE high/critical detectado.${RESET}"
    fi
else
    echo -e "${YELLOW}[!] Sem alvos para scan de CVE.${RESET}"
fi

# --- 8.3: Secrets e tokens (GAU + JS vivos + Arjun) ---
{
    cat "$WORKSPACE/gau_vivas.txt"
    cat "$WORKSPACE/js_alive.txt"
    cat "$WORKSPACE/params_arjun.txt"
} 2>/dev/null | sort -u > "$WORKSPACE/nuclei_secrets_targets.txt" || true

if [ -s "$WORKSPACE/nuclei_secrets_targets.txt" ]; then
    echo -e "${BLUE}[i] 8.3 Secrets/tokens (GAU + JS + Arjun — $(wc -l < "$WORKSPACE/nuclei_secrets_targets.txt") alvos)...${RESET}"
    nuclei -l "$WORKSPACE/nuclei_secrets_targets.txt" \
           -t http/exposures/ \
           -tags token,secret,api-key,exposure,leak \
           -severity low,medium,high,critical \
           -rl 30 \
           -timeout 5 \
           -o "$WORKSPACE/nuclei_secrets.txt" -silent \
           || echo -e "${YELLOW}[!] Nuclei secrets completou com erros.${RESET}"
else
    echo -e "${YELLOW}[!] Sem alvos para scan de secrets.${RESET}"
fi

# ==========================================================
# RELATORIO FINAL
# ==========================================================

DURATION=$SECONDS
echo -e "\n${CYAN}+======================================================+${RESET}"
printf "${CYAN}|  TRIAGEMASTER — %02dm %02ds%-31s|${RESET}\n" \
    "$(( DURATION / 60 ))" "$(( DURATION % 60 ))" ""
echo -e "${CYAN}+======================================================+${RESET}"

echo -e "\n${CYAN}-- Recon / Superficie --------------------------------${RESET}"
printf "  Subdominios brutos     : %s\n" "$(wc -l < "$WORKSPACE/subs_raw.txt")"
printf "  Com DNS ativo          : %s\n" "$(wc -l < "$WORKSPACE/subs_resolved.txt")"
printf "  Web services vivos     : %s\n" "$(wc -l < "$WORKSPACE/urls.txt")"
printf "  JS endpoints extraidos : %s\n" "$(wc -l < "$WORKSPACE/js_endpoints.txt")"
printf "  Params historicos      : %s\n" "$(wc -l < "$WORKSPACE/params_sqli.txt")"
printf "  Params Arjun (novos)   : %s\n" "$(wc -l < "$WORKSPACE/params_arjun.txt")"

echo -e "\n${CYAN}-- Alertas Criticos ----------------------------------${RESET}"

# Takeover
if [ -s "$WORKSPACE/takeover_nuclei.txt" ]; then
    echo -e "  ${RED}[!!!] TAKEOVER      : $(wc -l < "$WORKSPACE/takeover_nuclei.txt") finding(s) -> takeover_nuclei.txt${RESET}"
else
    echo -e "  Takeover            : (limpo)"
fi

# Infra exposta
if [ -s "$WORKSPACE/infra_exposed.txt" ]; then
    echo -e "  ${RED}[!!!] Infra Exposta : $(wc -l < "$WORKSPACE/infra_exposed.txt") host(s) -> infra_exposed.txt${RESET}"
else
    echo -e "  Infra Exposta       : (limpa)"
fi

# Secrets TruffleHog
SECRETS_V_FINAL=$(grep -c '"DetectorName"' "$WORKSPACE/trufflehog_verified.json" 2>/dev/null || echo 0)
if [[ $SECRETS_V_FINAL -gt 0 ]]; then
    echo -e "  ${RED}[!!!] Secrets OK    : $SECRETS_V_FINAL confirmado(s) -> trufflehog_verified.json${RESET}"
else
    echo -e "  Secrets VERIFIED    : (nenhum confirmado)"
fi
SECRETS_ALL_FINAL=$(grep -c '"DetectorName"' "$WORKSPACE/trufflehog_all.json" 2>/dev/null || echo 0)
echo -e "  ${YELLOW}Secrets ALL         : $SECRETS_ALL_FINAL total (inclui nao verificados) -> trufflehog_all.json${RESET}"

# CVEs
if [ -s "$WORKSPACE/nuclei_cves.txt" ]; then
    echo -e "  ${RED}[!!!] CVEs          : $(wc -l < "$WORKSPACE/nuclei_cves.txt") finding(s) -> nuclei_cves.txt${RESET}"
else
    echo -e "  CVEs                : (nenhum high/critical)"
fi

# WAF
echo -e "  WAF Detectado       : ${WAF_DETECTED:-0} host(s) -> waf_results.txt"

echo -e "\n${CYAN}-- Nuclei: Inventario (paineis/misconfig/tech) ------${RESET}"
print_severity_table "$WORKSPACE/nuclei_inventory.txt"

echo -e "\n${CYAN}-- Nuclei: CVEs (high/critical) ---------------------${RESET}"
print_severity_table "$WORKSPACE/nuclei_cves.txt"

echo -e "\n${CYAN}-- Nuclei: Secrets / Exposures ----------------------${RESET}"
print_severity_table "$WORKSPACE/nuclei_secrets.txt"

echo -e "\n${CYAN}-- Web Services com Tags (ScopeSentry) --------------${RESET}"
if [ -f "$WORKSPACE/alive.json" ]; then
    jq -r 'select(.tags | length > 0) | "  [\(.tags | join(","))] \(.url)"' \
        "$WORKSPACE/alive.json" 2>/dev/null | head -20 || true
fi

echo -e "\n${CYAN}-- Arquivos do Workspace -----------------------------${RESET}"
echo -e "  $WORKSPACE/"
ls -lh "$WORKSPACE/" | awk 'NR>1 {printf "    %-40s %s\n", $9, $5}'

echo -e "\n${CYAN}Triagem Finalizada. Boa cacada!${RESET}\n"
