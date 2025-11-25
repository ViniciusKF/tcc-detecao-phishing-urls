"""
PhishGuard - Extração de Características de URLs

Este módulo implementa a extração de 18 características (features) lexicais e estruturais
de URLs para detecção de phishing. A abordagem é puramente URL-only, não requerendo
acesso ao conteúdo da página ou consultas externas (DNS/WHOIS).

Autor: Projeto PhishGuard
Versão: 1.0
Data: Novembro 2024
"""

from __future__ import annotations
import re, urllib.parse
from typing import Dict, List

# Lista de palavras suspeitas comumente usadas em phishing
SUSPECT_WORDS = [
    "login","verify","update","secure","account","bank","confirm",
    "password","reset","gift","free","promo","win","bonus",
]

# Ordem das features no vetor de características (IMPORTANTE: não alterar)
FEATURE_ORDER: List[str] = [
    "len_url","len_host","num_dots","num_hyphens","num_at","num_digits",
    "num_params","num_special","has_ip_host","uses_https","scheme_is_http",
    "https_in_path","many_subdomains","suspicious_words","host_has_suspicious",
    "has_long_path","very_long_url","auth_terms_http",
]

# Labels legíveis para cada feature (para exibição ao usuário)
FEATURE_LABELS = {
    "len_url": "URL longa",
    "len_host": "Host longo",
    "num_dots": "Muitos pontos no host",
    "num_hyphens": "Muitos hífens",
    "num_at": "Uso de '@' na URL",
    "num_digits": "Muitos dígitos",
    "num_params": "Parâmetros demais",
    "num_special": "Muitos caracteres especiais",
    "has_ip_host": "Host é endereço IP",
    "uses_https": "Conexão HTTPS",
    "scheme_is_http": "Conexão HTTP (sem HTTPS)",
    "https_in_path": "'https' no caminho/params",
    "many_subdomains": "Excesso de subdomínios",
    "suspicious_words": "Palavras sensíveis na URL",
    "host_has_suspicious": "Palavras sensíveis no host",
    "has_long_path": "Caminho muito longo",
    "very_long_url": "URL muito longa",
    "auth_terms_http": "HTTP + termos de autenticação",
}

def _is_ip(host: str) -> bool:
    """
    Verifica se o hostname é um endereço IP (formato IPv4).
    
    Args:
        host: Hostname da URL
        
    Returns:
        True se for um IP, False caso contrário
        
    Exemplo:
        >>> _is_ip("192.168.1.1")
        True
        >>> _is_ip("example.com")
        False
    """
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))

def _count_subdomains(host: str) -> int:
    """
    Conta o número de subdomínios no hostname.
    
    Considera que um domínio típico tem 2 partes (exemplo.com),
    então subdomínios são as partes adicionais.
    
    Args:
        host: Hostname da URL
        
    Returns:
        Número de subdomínios (0 se não houver)
        
    Exemplo:
        >>> _count_subdomains("example.com")
        0
        >>> _count_subdomains("www.example.com")
        1
        >>> _count_subdomains("a.b.c.example.com")
        3
    """
    parts = [p for p in host.split(".") if p]
    return max(0, len(parts) - 2)

def extract_features(url: str) -> Dict[str, float]:
    """
    Extrai 18 características lexicais e estruturais da URL para detecção de phishing.
    
    Esta função implementa a engenharia de atributos baseada apenas na análise da URL,
    sem necessidade de acesso ao conteúdo da página ou consultas externas. É adequada
    para detecção em tempo real com baixa latência.
    
    Features Extraídas:
    -------------------
    
    1. **len_url** (float): Comprimento total da URL em caracteres.
       - Faixa típica: 20-100 (legítimas), 100-200 (suspeitas)
       - Exemplo: "https://example.com/path" -> 24.0
       - Justificativa: Phishings tendem a usar URLs longas para ofuscar o domínio real
    
    2. **len_host** (float): Comprimento do hostname (domínio + subdomínios).
       - Faixa típica: 10-30 (legítimas), 30-60 (suspeitas)
       - Exemplo: "subdomain.example.com" -> 22.0
       - Justificativa: Phishings usam domínios longos para imitar marcas conhecidas
    
    3. **num_dots** (float): Número de pontos no hostname.
       - Faixa típica: 1-2 (legítimas), 3-5 (suspeitas)
       - Exemplo: "a.b.c.example.com" -> 4.0
       - Justificativa: Múltiplos subdomínios são comuns em phishing
    
    4. **num_hyphens** (float): Número de hífens na URL completa.
       - Faixa típica: 0-2 (legítimas), 3-10 (suspeitas)
       - Exemplo: "my-secure-bank.com" -> 2.0
       - Justificativa: Phishings usam hífens para imitar domínios legítimos
    
    5. **num_at** (float): Número de '@' na URL.
       - Faixa típica: 0 (legítimas), 1+ (suspeitas)
       - Exemplo: "http://user@example.com" -> 1.0
       - Justificativa: '@' pode ser usado para ofuscar o domínio real
    
    6. **num_digits** (float): Número de dígitos na URL completa.
       - Faixa típica: 0-5 (legítimas), 6-20 (suspeitas)
       - Exemplo: "site123.com/page456" -> 6.0
       - Justificativa: Phishings frequentemente incluem números aleatórios
    
    7. **num_params** (float): Número de parâmetros na query string.
       - Faixa típica: 0-3 (legítimas), 4-10 (suspeitas)
       - Exemplo: "site.com?a=1&b=2" -> 2.0
       - Justificativa: Muitos parâmetros podem indicar redirecionamento malicioso
    
    8. **num_special** (float): Número de caracteres especiais (#, ?, %, &).
       - Faixa típica: 0-2 (legítimas), 3-10 (suspeitas)
       - Exemplo: "site.com?a=1&b=2#section" -> 3.0
       - Justificativa: Excesso de caracteres especiais é suspeito
    
    9. **has_ip_host** (float): Presença de endereço IP no hostname (0 ou 1).
       - Valores: 0.0 (não tem IP), 1.0 (tem IP)
       - Exemplo: "http://192.168.1.1/login" -> 1.0
       - Justificativa: URLs legítimas raramente usam IPs diretamente
    
    10. **uses_https** (float): Uso de HTTPS (0 ou 1).
        - Valores: 0.0 (HTTP), 1.0 (HTTPS)
        - Exemplo: "https://example.com" -> 1.0
        - Justificativa: Ausência de HTTPS é um indicador de risco
    
    11. **scheme_is_http** (float): Esquema é HTTP (0 ou 1).
        - Valores: 0.0 (não é HTTP), 1.0 (é HTTP)
        - Exemplo: "http://example.com" -> 1.0
        - Justificativa: HTTP é menos seguro que HTTPS
    
    12. **https_in_path** (float): Presença de "https" no caminho/query (0 ou 1).
        - Valores: 0.0 (não tem), 1.0 (tem)
        - Exemplo: "http://example.com/https-login" -> 1.0
        - Justificativa: Phishings tentam enganar colocando "https" no caminho
    
    13. **many_subdomains** (float): Excesso de subdomínios (>=3) (0 ou 1).
        - Valores: 0.0 (<=2 subdomínios), 1.0 (>=3 subdomínios)
        - Exemplo: "a.b.c.example.com" -> 1.0
        - Justificativa: Múltiplos subdomínios são raros em sites legítimos
    
    14. **suspicious_words** (float): Contagem de palavras suspeitas na URL.
        - Faixa típica: 0-1 (legítimas), 2-5 (suspeitas)
        - Palavras: login, verify, update, secure, account, bank, etc.
        - Exemplo: "site.com/login-verify-account" -> 3.0
        - Justificativa: Phishings usam termos relacionados a autenticação
    
    15. **host_has_suspicious** (float): Contagem de palavras suspeitas no hostname.
        - Faixa típica: 0 (legítimas), 1+ (suspeitas)
        - Exemplo: "secure-login.com" -> 2.0
        - Justificativa: Domínios legítimos raramente incluem termos de autenticação
    
    16. **has_long_path** (float): Caminho muito longo (>60 caracteres) (0 ou 1).
        - Valores: 0.0 (<=60), 1.0 (>60)
        - Exemplo: "/very/long/path/with/many/segments" -> 1.0 (se >60 chars)
        - Justificativa: Caminhos longos podem ofuscar a URL real
    
    17. **very_long_url** (float): URL muito longa (>100 caracteres) (0 ou 1).
        - Valores: 0.0 (<=100), 1.0 (>100)
        - Exemplo: URL com >100 caracteres -> 1.0
        - Justificativa: URLs longas são comuns em phishing
    
    18. **auth_terms_http** (float): HTTP + termos de autenticação (0 ou 1).
        - Valores: 0.0 (não), 1.0 (sim)
        - Exemplo: "http://example.com/login" -> 1.0
        - Justificativa: Sites legítimos de autenticação usam HTTPS
    
    Args:
        url (str): URL a ser analisada. Deve incluir esquema (http/https) ou será
                   assumido http:// por padrão.
    
    Returns:
        Dict[str, float]: Dicionário com 18 features numéricas (float).
                          Chaves: nomes das features conforme FEATURE_ORDER
                          Valores: valores numéricos das features
    
    Raises:
        Exception: Em caso de URL malformada, retorna features com valores padrão (0.0)
    
    Exemplo de Uso:
        >>> features = extract_features("https://example.com/path?param=1")
        >>> print(features['len_url'])
        36.0
        >>> print(features['has_ip_host'])
        0.0
        >>> print(features['uses_https'])
        1.0
    
    Notas:
        - Todas as features são numéricas (float) para compatibilidade com scikit-learn
        - Features booleanas são codificadas como 0.0 (False) ou 1.0 (True)
        - A ordem das features em FEATURE_ORDER deve ser mantida para compatibilidade
          com modelos treinados
    
    Referências:
        - Mohammad, R. M., et al. (2014). "Predicting Phishing Websites Based on 
          Self-Structuring Neural Network." Neural Computing and Applications.
        - Jain, A. K., & Gupta, B. B. (2016). "A Novel Approach to Protect Against 
          Phishing Attacks at Client Side Using Auto-Updated White-List."
    """
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    except Exception:
        # Em caso de erro, tenta adicionar esquema padrão
        parsed = urllib.parse.urlparse("http://" + url)

    host = (parsed.netloc or "").lower()
    path_q = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    full = (parsed.geturl() or url)
    scheme = parsed.scheme.lower()

    # Dicionário de features
    f: Dict[str, float] = {}
    
    # Features de comprimento
    f["len_url"] = float(len(full))
    f["len_host"] = float(len(host))
    
    # Features de contagem de caracteres
    f["num_dots"] = float(host.count("."))
    f["num_hyphens"] = float(full.count("-"))
    f["num_at"] = float(full.count("@"))
    f["num_digits"] = float(sum(c.isdigit() for c in full))
    f["num_params"] = float(parsed.query.count("="))
    f["num_special"] = float(sum(c in "#?%&" for c in full))
    
    # Features booleanas (codificadas como 0.0 ou 1.0)
    f["has_ip_host"] = float(_is_ip(host))
    f["uses_https"] = float(scheme == "https")
    f["scheme_is_http"] = float(scheme == "http")
    f["https_in_path"] = float("https" in path_q.lower())
    f["many_subdomains"] = float(_count_subdomains(host) >= 3)
    
    # Features de palavras suspeitas
    f["suspicious_words"] = float(sum(w in full.lower() for w in SUSPECT_WORDS))
    f["host_has_suspicious"] = float(sum(w in host for w in SUSPECT_WORDS))
    
    # Features de comprimento específico
    f["has_long_path"] = float(len(path_q) > 60)
    f["very_long_url"] = float(len(full) > 100)
    
    # Feature combinada (HTTP + termos de autenticação)
    f["auth_terms_http"] = float(
        scheme == "http" and any(w in (host + path_q) for w in ["login","verify","account","secure"])
    )
    
    return f

def vectorize_features(fmap: Dict[str, float]) -> list[float]:
    """
    Converte dicionário de features em vetor ordenado para uso com scikit-learn.
    
    Esta função garante que as features sejam ordenadas conforme FEATURE_ORDER,
    que é a ordem esperada pelo modelo treinado. Features ausentes são preenchidas
    com 0.0.
    
    Args:
        fmap (Dict[str, float]): Dicionário de features retornado por extract_features()
    
    Returns:
        list[float]: Lista ordenada de valores das features, pronta para predição
    
    Exemplo:
        >>> features = extract_features("https://example.com")
        >>> vector = vectorize_features(features)
        >>> len(vector)
        18
        >>> type(vector[0])
        <class 'float'>
    
    Notas:
        - A ordem das features é crítica para compatibilidade com modelos treinados
        - Features ausentes no dicionário são preenchidas com 0.0
        - Retorna sempre uma lista de 18 elementos (float)
    """
    return [float(fmap.get(k, 0.0)) for k in FEATURE_ORDER]

# ============================================================================
# Funções Auxiliares para Análise
# ============================================================================

def get_feature_count() -> int:
    """
    Retorna o número total de features extraídas.
    
    Returns:
        int: Número de features (18)
    """
    return len(FEATURE_ORDER)

def get_feature_names() -> List[str]:
    """
    Retorna lista com nomes de todas as features.
    
    Returns:
        List[str]: Lista de nomes das features
    """
    return FEATURE_ORDER.copy()

def get_feature_labels() -> Dict[str, str]:
    """
    Retorna dicionário com labels legíveis das features.
    
    Returns:
        Dict[str, str]: Mapeamento nome_feature -> label_legível
    """
    return FEATURE_LABELS.copy()

def print_features(fmap: Dict[str, float]) -> None:
    """
    Imprime features de forma legível para debug.
    
    Args:
        fmap: Dicionário de features retornado por extract_features()
    
    Exemplo:
        >>> features = extract_features("https://example.com")
        >>> print_features(features)
        len_url: 20.0 (URL longa)
        len_host: 11.0 (Host longo)
        ...
    """
    print("\n=== Features Extraídas ===")
    for key in FEATURE_ORDER:
        value = fmap.get(key, 0.0)
        label = FEATURE_LABELS.get(key, key)
        print(f"  {key:20s}: {value:6.1f}  ({label})")
    print("=" * 50 + "\n")
