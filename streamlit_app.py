import streamlit as st
import requests
import pandas as pd
import urllib3
from requests.auth import HTTPBasicAuth
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json

# ------------------------------------------------------
# 1. CONFIGURAÇÃO
# ------------------------------------------------------
st.set_page_config(page_title="Sentinel Monitor", layout="wide", page_icon="🛡️")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    TPOT_URL = st.secrets["TPOT_URL"]
    TPOT_USER = st.secrets["TPOT_USER"]
    TPOT_PASSWORD = st.secrets["TPOT_PASSWORD"]
    if TPOT_URL.endswith('/'): 
        TPOT_URL = TPOT_URL[:-1]
except KeyError as e:
    st.error(f"Erro: Falta a configuração {e}")
    st.stop()

ES_URL = f"{TPOT_URL}/es/logstash-*/_search"

# ------------------------------------------------------
# 2. LISTA BRANCA (Apenas Honeypots Reais)
# ------------------------------------------------------
REAL_HONEYPOTS = [
    "Cowrie", "cowrie", "Dionaea", "dionaea", "Honeytrap", "honeytrap",
    "ElasticPot", "elasticpot", "RDPY", "rdpy", "Mailoney", "mailoney",
    "Ciscoasa", "ciscoasa", "Medpot", "medpot", "Conpot", "conpot",
    "Tanner", "tanner", "Nginx", "NGINX", "nginx", "Honeytrap", "honeytrap",
    "H0neyTr4p", "h0neytr4p", "Sentrypeer", "sentrypeer", "Miniprint", "miniprint",
    "Honeyaml", "honeyaml", "Mailoney", "mailoney"
]

# ------------------------------------------------------
# 3. FILTROS E SIDEBAR
# ------------------------------------------------------
st.sidebar.header("⚙️ Configurações")
time_input = st.sidebar.selectbox("📅 Período:", 
    ["Últimas 24 Horas", "Últimos 7 Dias", "Últimos 30 Dias", "Tudo"])

time_map = {
    "Últimas 24 Horas": "now-24h",
    "Últimos 7 Dias": "now-7d",
    "Últimos 30 Dias": "now-30d",
    "Tudo": "all"
}
time_range = time_map[time_input]

show_details = st.sidebar.checkbox("🔍 Mostrar Detalhes Avançados", value=True)
auto_refresh = st.sidebar.checkbox("🔄 Auto-refresh (30s)", value=False)

if st.sidebar.button('🔄 Atualizar Agora', type="primary"):
    st.rerun()

st.sidebar.divider()
st.sidebar.subheader("📊 Sobre os Dados")
st.sidebar.info("Este dashboard analisa apenas ataques reais capturados por honeypots, ignorando ruído de rede e logs do P0f/Suricata e da Oracle.")

# Auto-refresh
if auto_refresh:
    st.sidebar.caption("⏰ Próxima atualização em 30s")
    import time
    time.sleep(30)
    st.rerun()

# ------------------------------------------------------
# 4. FUNÇÕES DE BUSCA COMPLETAS
# ------------------------------------------------------
def get_comprehensive_attack_data(time_range_val):
    
    # Busca todas as agregações possíveis para análise completa
    
    query = {
        "from": 0,
        "size": 0,  # Apenas agregações
        "track_total_hits": True,
        "query": {
            "bool": {
                "must": [
                    {"terms": {"type.keyword": REAL_HONEYPOTS}}
                ],
                "must_not": [
                    # Filtro para remover porta 60973
                    {"term": {"dest_port": 60973}},
                    # Filtro para remover Oracle Corporation
                    {"term": {"geoip.as_org.keyword": "Oracle Corporation"}},
                    # Filtros para remover IPs locais/privados
                    {"wildcard": {"src_ip.keyword": "10.*"}},
                    {"wildcard": {"src_ip.keyword": "192.168.*"}},
                    {"wildcard": {"src_ip.keyword": "172.16.*"}},
                    {"wildcard": {"src_ip.keyword": "172.17.*"}},
                    {"wildcard": {"src_ip.keyword": "172.18.*"}},
                    {"wildcard": {"src_ip.keyword": "172.19.*"}},
                    {"wildcard": {"src_ip.keyword": "172.20.*"}},
                    {"wildcard": {"src_ip.keyword": "172.21.*"}},
                    {"wildcard": {"src_ip.keyword": "172.22.*"}},
                    {"wildcard": {"src_ip.keyword": "172.23.*"}},
                    {"wildcard": {"src_ip.keyword": "172.24.*"}},
                    {"wildcard": {"src_ip.keyword": "172.25.*"}},
                    {"wildcard": {"src_ip.keyword": "172.26.*"}},
                    {"wildcard": {"src_ip.keyword": "172.27.*"}},
                    {"wildcard": {"src_ip.keyword": "172.28.*"}},
                    {"wildcard": {"src_ip.keyword": "172.29.*"}},
                    {"wildcard": {"src_ip.keyword": "172.30.*"}},
                    {"wildcard": {"src_ip.keyword": "172.31.*"}},
                    {"wildcard": {"src_ip.keyword": "127.*"}},
                    {"wildcard": {"src_ip.keyword": "169.254.*"}},
                    {"wildcard": {"src_ip.keyword": "fc00:*"}},
                    {"wildcard": {"src_ip.keyword": "fd00:*"}},
                    {"wildcard": {"src_ip.keyword": "fe80:*"}},
                    {"term": {"src_ip.keyword": "::1"}}
                ]
            }
        },
        "aggs": {
            # === CONTADORES BÁSICOS ===
            "unique_attackers": {
                "cardinality": {"field": "src_ip.keyword"}
            },
            "unique_countries": {
                "cardinality": {"field": "geoip.country_name.keyword"}
            },
            "unique_ports": {
                "cardinality": {"field": "dest_port"}
            },
            
            # === TOP RANKINGS ===
            "top_ips": {
                "terms": {"field": "src_ip.keyword", "size": 20}
            },
            "top_countries": {
                "terms": {"field": "geoip.country_name.keyword", "size": 20}
            },
            "top_cities": {
                "terms": {"field": "geoip.city_name.keyword", "size": 15}
            },
            "top_honeypots": {
                "terms": {"field": "type.keyword", "size": 30}
            },
            "top_ports": {
                "terms": {"field": "dest_port", "size": 20}
            },
            "top_asn": {
                "terms": {"field": "geoip.as_org.keyword", "size": 15}
            },
            
            # === GEOLOCALIZAÇÃO PARA MAPA ===
            "geo_points": {
                "terms": {
                    "field": "geoip.country_name.keyword",
                    "size": 100
                },
                "aggs": {
                    "centroid": {
                        "geo_centroid": {
                            "field": "geoip.location"
                        }
                    }
                }
            },
            
            # === COMANDOS E PAYLOADS ===
            "top_commands": {
                "terms": {"field": "input.keyword", "size": 30}
            },
            "top_usernames": {
                "terms": {"field": "username.keyword", "size": 20}
            },
            "top_passwords": {
                "terms": {"field": "password.keyword", "size": 20}
            },
            "top_urls": {
                "terms": {"field": "url.keyword", "size": 15}
            },
            "top_user_agents": {
                "terms": {"field": "http_user_agent.keyword", "size": 15}
            },
            "top_malware": {
                "terms": {"field": "shasum.keyword", "size": 10}
            },
            
            # === PROTOCOLOS E MÉTODOS ===
            "top_protocols": {
                "terms": {"field": "protocol.keyword", "size": 10}
            },
            "top_http_methods": {
                "terms": {"field": "http_method.keyword", "size": 10}
            },
            "top_ssh_versions": {
                "terms": {"field": "ssh_version.keyword", "size": 10}
            },
            
            # === ANÁLISE TEMPORAL ===
            "attacks_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "hour",
                    "min_doc_count": 1
                }
            },
            "attacks_by_day_of_week": {
                "terms": {
                    "script": {
                        "source": "doc['@timestamp'].value.dayOfWeek",
                        "lang": "painless"
                    },
                    "size": 7
                }
            },
            "attacks_by_hour": {
                "terms": {
                    "script": {
                        "source": "doc['@timestamp'].value.hour",
                        "lang": "painless"
                    },
                    "size": 24
                }
            },
            
            # === ANÁLISE GEOGRÁFICA DETALHADA ===
            "top_continents": {
                "terms": {"field": "geoip.continent_code.keyword", "size": 10}
            },
            "top_regions": {
                "terms": {"field": "geoip.region_name.keyword", "size": 15}
            },
            
            # === ANÁLISE DE SESSÕES ===
            "top_session_ids": {
                "terms": {"field": "session.keyword", "size": 10}
            },
            
            # === ANÁLISE DE ARQUIVOS ===
            "top_file_types": {
                "terms": {"field": "file_type.keyword", "size": 10}
            },
            "top_filenames": {
                "terms": {"field": "filename.keyword", "size": 15}
            },
            
            # === ESTATÍSTICAS ===
            "avg_session_duration": {
                "avg": {"field": "session_duration"}
            },
            "total_bytes_transferred": {
                "sum": {"field": "bytes"}
            }
        }
    }
    
    if time_range_val != "all":
        query["query"]["bool"]["filter"] = [
            {
                "range": {
                    "@timestamp": {
                        "gte": time_range_val,
                        "lte": "now"
                    }
                }
            }
        ]
    
    try:
        response = requests.post(
            ES_URL,
            auth=HTTPBasicAuth(TPOT_USER, TPOT_PASSWORD),
            headers={"Content-Type": "application/json"},
            json=query,
            verify=False,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"❌ Erro ao buscar dados agregados: {e}")
        return None

def get_detailed_attack_logs(time_range_val, max_size=500):
    
    # Busca os últimos N registros detalhados para análise granular
    
    query = {
        "from": 0,
        "size": max_size,
        "track_total_hits": True,
        "query": {
            "bool": {
                "must": [
                    {"terms": {"type.keyword": REAL_HONEYPOTS}}
                ],
                "must_not": [
                    # Filtro para remover porta 60973
                    {"term": {"dest_port": 60973}},
                    # Filtro para remover Oracle Corporation
                    {"term": {"geoip.as_org.keyword": "Oracle Corporation"}},
                    # Filtros para remover IPs locais/privados
                    {"wildcard": {"src_ip.keyword": "10.*"}},
                    {"wildcard": {"src_ip.keyword": "192.168.*"}},
                    {"wildcard": {"src_ip.keyword": "172.16.*"}},
                    {"wildcard": {"src_ip.keyword": "172.17.*"}},
                    {"wildcard": {"src_ip.keyword": "172.18.*"}},
                    {"wildcard": {"src_ip.keyword": "172.19.*"}},
                    {"wildcard": {"src_ip.keyword": "172.20.*"}},
                    {"wildcard": {"src_ip.keyword": "172.21.*"}},
                    {"wildcard": {"src_ip.keyword": "172.22.*"}},
                    {"wildcard": {"src_ip.keyword": "172.23.*"}},
                    {"wildcard": {"src_ip.keyword": "172.24.*"}},
                    {"wildcard": {"src_ip.keyword": "172.25.*"}},
                    {"wildcard": {"src_ip.keyword": "172.26.*"}},
                    {"wildcard": {"src_ip.keyword": "172.27.*"}},
                    {"wildcard": {"src_ip.keyword": "172.28.*"}},
                    {"wildcard": {"src_ip.keyword": "172.29.*"}},
                    {"wildcard": {"src_ip.keyword": "172.30.*"}},
                    {"wildcard": {"src_ip.keyword": "172.31.*"}},
                    {"wildcard": {"src_ip.keyword": "127.*"}},
                    {"wildcard": {"src_ip.keyword": "169.254.*"}},
                    {"wildcard": {"src_ip.keyword": "fc00:*"}},
                    {"wildcard": {"src_ip.keyword": "fd00:*"}},
                    {"wildcard": {"src_ip.keyword": "fe80:*"}},
                    {"term": {"src_ip.keyword": "::1"}}
                ]
            }
        },
        "sort": [
            {"@timestamp": {"order": "desc"}}
        ]
    }
    
    if time_range_val != "all":
        query["query"]["bool"]["filter"] = [
            {
                "range": {
                    "@timestamp": {
                        "gte": time_range_val,
                        "lte": "now"
                    }
                }
            }
        ]
    
    try:
        response = requests.post(
            ES_URL,
            auth=HTTPBasicAuth(TPOT_USER, TPOT_PASSWORD),
            headers={"Content-Type": "application/json"},
            json=query,
            verify=False,
            timeout=30
        )
        response.raise_for_status()
        return response.json()
    except Exception as e:
        st.error(f"❌ Erro ao buscar logs detalhados: {e}")
        return None

# ------------------------------------------------------
# 5. BUSCAR DADOS
# ------------------------------------------------------
with st.spinner("🔍 Carregando dados do Elasticsearch..."):
    data = get_comprehensive_attack_data(time_range)
    detailed_data = get_detailed_attack_logs(time_range) if show_details else None

if not data:
    st.error("❌ Falha ao conectar com o Elasticsearch. Verifique as credenciais e a URL.")
    st.stop()

# Extrair dados
total_attacks = data.get('hits', {}).get('total', {}).get('value', 0)
agg = data.get('aggregations', {})

if total_attacks == 0:
    st.warning("⚠️ Nenhum ataque detectado no período selecionado.")
    st.stop()

# ------------------------------------------------------
# 6. HEADER COM LOGO E TÍTULO
# ------------------------------------------------------
header_col1, header_col2 = st.columns([1, 4])
with header_col2:
    st.title("🛡️Sentinel Dashboard - Honeypot Monitor")
    st.info("💡 **Dados filtrados:** Removidos ruídos de infraestrutura (Porta 60973) para foco em ataques orgânicos reais.")
    st.caption(f"📅 Período: **{time_input}** | 🔄 Última Atualização: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")

st.divider()

# ======================================================
# SEÇÃO 1: MÉTRICAS PRINCIPAIS
# ======================================================
st.header("📊 Visão Geral")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        label="🎯 Total de Ataques",
        value=f"{total_attacks:,}",
        delta="Apenas ataques reais"
    )

with col2:
    unique_attackers = agg.get('unique_attackers', {}).get('value', 0)
    st.metric(
        label="😈 IPs Únicos",
        value=f"{unique_attackers:,}",
        delta=f"{(unique_attackers/total_attacks*100):.1f}% do total" if total_attacks > 0 else "0%"
    )

with col3:
    unique_countries = agg.get('unique_countries', {}).get('value', 0)
    st.metric(
        label="🌍 Países Diferentes",
        value=f"{unique_countries}",
        delta="Alcance Global"
    )

with col4:
    unique_ports = agg.get('unique_ports', {}).get('value', 0)
    st.metric(
        label="🔌 Portas Atacadas",
        value=f"{unique_ports}",
        delta="Vetores de Ataque"
    )

st.divider()

# ======================================================
# SEÇÃO 2: MAPA GLOBAL DE ATAQUES
# ======================================================
st.header("🗺️ Mapa Global de Ataques")

geo_points = agg.get('geo_points', {}).get('buckets', [])
if geo_points:
    map_data = []
    for bucket in geo_points:
        country = bucket['key']
        count = bucket['doc_count']
        centroid = bucket.get('centroid', {}).get('location', {})
        
        if centroid and 'lat' in centroid and 'lon' in centroid:
            map_data.append({
                'country': country,
                'ataques': count,
                'lat': centroid['lat'],
                'lon': centroid['lon']
            })
    
    if map_data:
        geo_df = pd.DataFrame(map_data)
        
        # Agregar por país para criar bolhas
        country_attacks = geo_df.groupby(['country', 'lat', 'lon']).size().reset_index(name='ataques')
        
        # Criar mapa com tema original
        fig_map = px.scatter_geo(
            country_attacks,
            lat='lat',
            lon='lon',
            size='ataques',
            hover_name='country',
            hover_data={'ataques': ':,', 'lat': False, 'lon': False},
            color='ataques',
            color_continuous_scale=[
                [0, '#0a0e27'],
                [0.3, '#8b00ff'],
                [0.6, '#ff00ff'],
                [0.85, '#ff0040'],
                [1, '#ff0000']
            ],
            size_max=70,
            projection='natural earth',
            title=f'<b>🌍 MAPA GLOBAL DE ATAQUES CIBERNÉTICOS</b><br><sub>{total_attacks:,} ataques detectados</sub>'
        )
        
        fig_map.update_layout(
            height=650,
            font=dict(family="Courier New, monospace", color="#00ff41", size=12),
            title_font=dict(size=18, color="#00ffff"),
            geo=dict(
                showframe=True,
                framecolor='#00ffff',
                framewidth=2,
                showcoastlines=True,
                coastlinecolor='#0066ff',
                projection_type='natural earth',
                bgcolor='#0a0e27',
                showland=True,
                landcolor='#0d1117',
                showlakes=True,
                lakecolor='#050811',
                showcountries=True,
                countrycolor='#1a3a52'
            ),
            paper_bgcolor='#0d1117',
            plot_bgcolor='#0d1117',
            coloraxis_colorbar=dict(
                title=dict(
                    text="<b>Ataques</b>",
                    font=dict(color="#00ffff")
                ),
                tickfont=dict(color="#00ff41"),
                bgcolor='rgba(13, 17, 23, 0.8)',
                bordercolor='#00ffff',
                borderwidth=2
            )
        )
        
        fig_map.update_traces(
            marker=dict(
                line=dict(width=2, color='#00ffff'),
                opacity=0.85
            )
        )
        
        st.plotly_chart(fig_map, width="stretch", config={'displayModeBar': False})
else:
    st.warning("⚠️ Não há dados de geolocalização disponíveis para este período")

st.divider()

# ======================================================
# SEÇÃO 3: HONEYPOTS MAIS ATACADOS
# ======================================================
st.header("🍯 Honeypots Mais Atacados")

honeypots = agg.get('top_honeypots', {}).get('buckets', [])
if honeypots:
    hp_df = pd.DataFrame([
        {'Honeypot': b['key'], 'Ataques': b['doc_count'], 'Percentual': f"{(b['doc_count']/total_attacks*100):.2f}%"} 
        for b in honeypots
    ])
    
    col_hp1, col_hp2 = st.columns([2, 1])
    
    with col_hp1:
        fig_hp = px.bar(
            hp_df, 
            x='Ataques', 
            y='Honeypot', 
            orientation='h',
            title="Distribuição de Ataques por Honeypot",
            color='Ataques',
            color_continuous_scale='Reds',
            text='Percentual'
        )
        fig_hp.update_layout(height=500, showlegend=False)
        st.plotly_chart(fig_hp, width="stretch")
    
    with col_hp2:
        st.dataframe(hp_df, width='stretch', hide_index=True, height=500)

st.divider()

# ======================================================
# SEÇÃO 4: ANÁLISE GEOGRÁFICA DETALHADA
# ======================================================
st.header("🌍 Origem Geográfica dos Ataques")

geo_col1, geo_col2 = st.columns(2)

with geo_col1:
    st.subheader("🗺️ Top 20 Países")
    countries = agg.get('top_countries', {}).get('buckets', [])
    if countries:
        country_df = pd.DataFrame([
            {
                'País': b['key'], 
                'Ataques': b['doc_count'],
                'Percentual': f"{(b['doc_count']/total_attacks*100):.2f}%"
            } 
            for b in countries
        ])
        
        fig_countries = px.bar(
            country_df.head(10), 
            x='Ataques', 
            y='País', 
            orientation='h',
            title="Top 10 Países Atacantes",
            color='Ataques',
            color_continuous_scale='Reds',
            text='Percentual'
        )
        fig_countries.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig_countries, width="stretch")
        
        st.dataframe(country_df, width="stretch", hide_index=True, height=300)

with geo_col2:
    st.subheader("🏙️ Top 15 Cidades")
    cities = agg.get('top_cities', {}).get('buckets', [])
    if cities:
        city_df = pd.DataFrame([
            {'Cidade': b['key'], 'Ataques': b['doc_count']} 
            for b in cities
        ])
        st.dataframe(city_df, width="stretch", hide_index=True, height=700)

st.divider()

# ======================================================
# SEÇÃO 5: ANÁLISE TEMPORAL
# ======================================================
st.header("⏰ Análise Temporal")

time_col1, time_col2 = st.columns(2)

with time_col1:
    st.subheader("📈 Ataques ao Longo do Tempo")
    attacks_time = agg.get('attacks_over_time', {}).get('buckets', [])
    if attacks_time:
        time_df = pd.DataFrame([
            {
                'Data/Hora': datetime.fromisoformat(b['key_as_string'].replace('Z', '+00:00')),
                'Ataques': b['doc_count']
            } 
            for b in attacks_time
        ])
        
        fig_time = px.line(
            time_df, 
            x='Data/Hora', 
            y='Ataques',
            title="Evolução Temporal dos Ataques",
            markers=True
        )
        fig_time.update_traces(line_color='#dc143c')
        st.plotly_chart(fig_time, width="stretch")

with time_col2:
    st.subheader("📅 Distribuição por Dia da Semana")
    days_week = agg.get('attacks_by_day_of_week', {}).get('buckets', [])
    if days_week:
        day_names = {1: 'Segunda', 2: 'Terça', 3: 'Quarta', 4: 'Quinta', 5: 'Sexta', 6: 'Sábado', 7: 'Domingo'}
        day_df = pd.DataFrame([
            {
                'Dia': day_names.get(b['key'], 'N/A'),
                'Ataques': b['doc_count']
            } 
            for b in sorted(days_week, key=lambda x: x['key'])
        ])
        
        fig_days = px.bar(
            day_df, 
            x='Dia', 
            y='Ataques',
            title="Ataques por Dia da Semana",
            color='Ataques',
            color_continuous_scale='Reds'
        )
        st.plotly_chart(fig_days, width="stretch")
    
    st.subheader("🕐 Distribuição por Hora do Dia")
    hours = agg.get('attacks_by_hour', {}).get('buckets', [])
    if hours:
        hour_df = pd.DataFrame([
            {
                'Hora': f"{int(b['key']):02d}:00",
                'Ataques': b['doc_count']
            } 
            for b in sorted(hours, key=lambda x: x['key'])
        ])
        
        fig_hours = px.bar(
            hour_df, 
            x='Hora', 
            y='Ataques',
            title="Ataques por Hora",
            color='Ataques',
            color_continuous_scale='Reds'
        )
        st.plotly_chart(fig_hours, width="stretch")

st.divider()

# ======================================================
# SEÇÃO 6: ANÁLISE DE PROTOCOLOS E PORTAS
# ======================================================
st.header("🔌 Protocolos e Portas Atacadas")

proto_col1, proto_col2 = st.columns(2)

with proto_col1:
    st.subheader("⚙️ Protocolos Mais Atacados")
    protocols = agg.get('top_protocols', {}).get('buckets', [])
    if protocols:
        proto_df = pd.DataFrame([
            {'Protocolo': b['key'], 'Ataques': b['doc_count']} 
            for b in protocols
        ])
        
        fig_proto = px.pie(
            proto_df, 
            values='Ataques', 
            names='Protocolo',
            title="Distribuição por Protocolo",
            color_discrete_sequence=px.colors.sequential.Reds_r
        )
        st.plotly_chart(fig_proto, width="stretch")

with proto_col2:
    st.subheader("🔌 Top 20 Portas Atacadas")
    ports = agg.get('top_ports', {}).get('buckets', [])
    if ports:
        port_df = pd.DataFrame([
            {
                'Porta': b['key'], 
                'Ataques': b['doc_count'],
                'Percentual': f"{(b['doc_count']/total_attacks*100):.2f}%"
            } 
            for b in ports
        ])
        st.dataframe(port_df, width="stretch", hide_index=True, height=400)

st.divider()

# ======================================================
# SEÇÃO 7: COMANDOS E PAYLOADS
# ======================================================
st.header("💻 Comandos e Payloads Capturados")

cmd_col1, cmd_col2 = st.columns([3, 2])

with cmd_col1:
    st.subheader("⌨️ Top 30 Comandos Executados")
    commands = agg.get('top_commands', {}).get('buckets', [])
    if commands:
        cmd_df = pd.DataFrame([
            {
                'Comando': b['key'][:100], 
                'Execuções': b['doc_count'],
                'Percentual': f"{(b['doc_count']/total_attacks*100):.2f}%"
            } 
            for b in commands if b['key']
        ])
        st.dataframe(cmd_df, width="stretch", hide_index=True, height=500)
    else:
        st.info("Nenhum comando capturado neste período")

with cmd_col2:
    st.subheader("🌐 URLs Acessadas")
    urls = agg.get('top_urls', {}).get('buckets', [])
    if urls:
        url_df = pd.DataFrame([
            {'URL': b['key'][:80], 'Acessos': b['doc_count']} 
            for b in urls if b['key']
        ])
        st.dataframe(url_df, width="stretch", hide_index=True, height=250)
    else:
        st.info("Nenhuma URL capturada")
    
    st.subheader("🖥️ User-Agents")
    uas = agg.get('top_user_agents', {}).get('buckets', [])
    if uas:
        ua_df = pd.DataFrame([
            {'User-Agent': b['key'][:60], 'Ocorrências': b['doc_count']} 
            for b in uas if b['key']
        ])
        st.dataframe(ua_df, width="stretch", hide_index=True, height=230)

st.divider()

# ======================================================
# SEÇÃO 8: CREDENCIAIS CAPTURADAS
# ======================================================
st.header("🔐 Credenciais Capturadas")

cred_col1, cred_col2 = st.columns(2)

with cred_col1:
    st.subheader("👤 Top 20 Usernames")
    users = agg.get('top_usernames', {}).get('buckets', [])
    if users:
        user_df = pd.DataFrame([
            {'Username': b['key'], 'Tentativas': b['doc_count']} 
            for b in users if b['key']
        ])
        st.dataframe(user_df, width="stretch", hide_index=True, height=400)
    else:
        st.info("Nenhum username capturado")

with cred_col2:
    st.subheader("🔑 Top 20 Passwords")
    passwords = agg.get('top_passwords', {}).get('buckets', [])
    if passwords:
        pass_df = pd.DataFrame([
            {'Password': b['key'], 'Tentativas': b['doc_count']} 
            for b in passwords if b['key']
        ])
        st.dataframe(pass_df, width="stretch", hide_index=True, height=400)
    else:
        st.info("Nenhuma senha capturada")

st.divider()

# ======================================================
# SEÇÃO 9: MALWARE E ARQUIVOS
# ======================================================
st.header("🦠 Malware e Arquivos")

malware_col1, malware_col2 = st.columns(2)

with malware_col1:
    st.subheader("📦 Malware Detectado (SHA)")
    malware = agg.get('top_malware', {}).get('buckets', [])
    if malware:
        mal_df = pd.DataFrame([
            {'SHA256': b['key'], 'Downloads': b['doc_count']} 
            for b in malware if b['key']
        ])
        st.dataframe(mal_df, width="stretch", hide_index=True)
    else:
        st.info("Nenhum malware detectado neste período")

with malware_col2:
    st.subheader("📄 Arquivos Baixados")
    files = agg.get('top_filenames', {}).get('buckets', [])
    if files:
        file_df = pd.DataFrame([
            {'Arquivo': b['key'], 'Downloads': b['doc_count']} 
            for b in files if b['key']
        ])
        st.dataframe(file_df, width="stretch", hide_index=True)
    else:
        st.info("Nenhum arquivo capturado")

st.divider()

# ======================================================
# SEÇÃO 10: TOP ATACANTES
# ======================================================
st.header("😈 Top Atacantes e Provedores")

attacker_col1, attacker_col2 = st.columns(2)

with attacker_col1:
    st.subheader("🌐 Top 20 IPs Atacantes")
    ips = agg['top_ips']['buckets']
    if ips:
        ip_df = pd.DataFrame([
            {
                'IP': b['key'], 
                'Ataques': b['doc_count'],
                'Percentual': f"{(b['doc_count']/total_attacks*100):.2f}%"
            } 
            for b in ips
        ])
        st.dataframe(ip_df, width="stretch", hide_index=True, height=500)

with attacker_col2:
    st.subheader("🏢 Top 15 ASN/Provedores")
    asns = agg['top_asn']['buckets']
    if asns:
        asn_df = pd.DataFrame([
            {'Provedor': b['key'], 'Ataques': b['doc_count']} 
            for b in asns
        ])
        st.dataframe(asn_df, width="stretch", hide_index=True, height=500)

st.divider()

# ======================================================
# SEÇÃO 11: DETALHES COMPLETOS DOS ATAQUES
# ======================================================
if show_details and detailed_data:
    st.header("📋 Registro Detalhado de Ataques (Últimos 500)")
    
    hits = detailed_data.get('hits', {}).get('hits', [])
    
    if hits:
        detailed_attacks = []
        for hit in hits:
            src = hit['_source']
            detailed_attacks.append({
                "🕐 Timestamp": src.get('@timestamp', 'N/A'),
                "🍯 Honeypot": src.get('type', 'N/A'),
                "🌐 IP": src.get('src_ip', 'N/A'),
                "🔌 Porta": src.get('dest_port', 'N/A'),
                "🌍 País": src.get('geoip', {}).get('country_name', 'N/A'),
                "🏙️ Cidade": src.get('geoip', {}).get('city_name', 'N/A'),
                "🏢 ASN": src.get('geoip', {}).get('as_org', 'N/A')[:40],
                "⚙️ Protocolo": src.get('protocol', 'N/A'),
                "👤 Username": src.get('username', 'N/A'),
                "🔑 Password": src.get('password', 'N/A'),
                "💻 Comando": str(src.get('commands', ''))[:100],
                "🌐 URL": src.get('url', 'N/A')[:60],
                "🖥️ User-Agent": src.get('http_user_agent', 'N/A')[:50],
                "📄 Arquivo": src.get('filename', 'N/A'),
                "🦠 SHA256": src.get('shasum', 'N/A')[:20],
                "🔢 Session": src.get('session', 'N/A')[:15],
                "📊 Bytes": src.get('bytes', 'N/A')
            })
        
        detail_df = pd.DataFrame(detailed_attacks)
        
        # Filtros interativos
        filter_col1, filter_col2, filter_col3 = st.columns(3)
        
        with filter_col1:
            filter_honeypot = st.multiselect("Filtrar por Honeypot:", 
                options=detail_df['🍯 Honeypot'].unique())
        with filter_col2:
            filter_country = st.multiselect("Filtrar por País:", 
                options=detail_df['🌍 País'].unique())
        with filter_col3:
            filter_protocol = st.multiselect("Filtrar por Protocolo:", 
                options=detail_df['⚙️ Protocolo'].unique())
        
        # Aplicar filtros
        filtered_df = detail_df.copy()
        if filter_honeypot:
            filtered_df = filtered_df[filtered_df['🍯 Honeypot'].isin(filter_honeypot)]
        if filter_country:
            filtered_df = filtered_df[filtered_df['🌍 País'].isin(filter_country)]
        if filter_protocol:
            filtered_df = filtered_df[filtered_df['⚙️ Protocolo'].isin(filter_protocol)]
        
        st.dataframe(filtered_df, width="stretch", hide_index=True, height=600)

st.divider()

# ======================================================
# FOOTER COM ESTATÍSTICAS EXTRAS
# ======================================================
col_footer_1, col_footer_2 = st.columns([3, 1])
with col_footer_1:
    st.caption("🛡️ **Sentinel Dashboard** | Monitorando ataques globais em tempo real.")
    st.caption("Arquitetura: T-Pot Multi Honeypot → Elastic Stack → Ngrok → Streamlit")

with col_footer_2:
    st.markdown(
        """
        <div style="text-align: right;">
            <a href="https://www.linkedin.com/in/khimira/" target="_blank" style="text-decoration: none;">
                <button style="background-color:#0077b5; color:white; border:none; padding:8px 16px; border-radius:4px; cursor:pointer;">
                    Conectar no LinkedIn 🔗
                </button>
            </a>
        </div>
        """,
        unsafe_allow_html=True
    )

with st.expander("📊 Estatísticas Adicionais"):
    stat_col1, stat_col2, stat_col3 = st.columns(3)
    
    with stat_col1:
        avg_duration = agg.get('avg_session_duration', {}).get('value', 0)
        if avg_duration:
            st.metric("⏱️ Duração Média Sessão", f"{avg_duration:.1f}s")
    
    with stat_col2:
        total_bytes = agg.get('total_bytes_transferred', {}).get('value', 0)
        if total_bytes:
            st.metric("📊 Bytes Transferidos", f"{total_bytes/1024/1024:.2f} MB")
    
    with stat_col3:
        st.metric("📅 Período Analisado", time_input)
