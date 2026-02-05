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
    "Tanner", "tanner", "Nginx", "NGINX", "nginx", "Honeytrap", "honeytrap", "H0neyTr4p", "h0neytr4p", "Sentrypeer", "sentrypeer"
]

# ------------------------------------------------------
# 3. FILTROS E SIDEBAR
# ------------------------------------------------------
st.sidebar.header("⚙️ Configurações")
time_input = st.sidebar.selectbox("📅 Período:", 
    ["Última Hora", "Últimas 6 Horas", "Últimas 24 Horas", "Últimos 7 Dias", "Últimos 30 Dias", "Tudo"])
    index=2

time_map = {
    "Última Hora": "now-1h",
    "Últimas 6 Horas": "now-6h",
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
st.sidebar.info("Este dashboard analisa apenas ataques reais capturados por honeypots, ignorando ruído de rede e logs do P0f/Suricata.")

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
                "terms": {"field": "commands.keyword", "size": 30}
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
            {"range": {"@timestamp": {"gte": time_range_val, "lte": "now"}}}
        ]

    try:
        r = requests.get(ES_URL, json=query, auth=HTTPBasicAuth(TPOT_USER, TPOT_PASSWORD), 
                        verify=False, timeout=30)
        return r.json() if r.status_code == 200 else None
    except Exception as e:
        st.error(f"Erro ao buscar dados agregados: {e}")
        return None


def get_detailed_attacks(time_range_val, limit=500):
    
    # Busca detalhada dos últimos ataques com TODOS os campos
    
    query = {
        "size": limit,
        "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["*"],  # Todos os campos
        "query": {
            "bool": {
                "must": [
                    {"terms": {"type.keyword": REAL_HONEYPOTS}}
                ]
            }
        }
    }
    
    if time_range_val != "all":
        query["query"]["bool"]["filter"] = [
            {"range": {"@timestamp": {"gte": time_range_val, "lte": "now"}}}
        ]

    try:
        r = requests.get(ES_URL, json=query, auth=HTTPBasicAuth(TPOT_USER, TPOT_PASSWORD), 
                        verify=False, timeout=30)
        return r.json() if r.status_code == 200 else None
    except Exception as e:
        st.error(f"Erro ao buscar ataques detalhados: {e}")
        return None


# ------------------------------------------------------
# 5. DASHBOARD COMPLETO
# ------------------------------------------------------
st.title("🛡️ Sentinel Dashboard - Análise Completa de Ameaças")
st.caption(f"📊 **Período:** {time_input} | 🕐 **Última Atualização:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# Buscar dados
with st.spinner("🔄 Carregando dados..."):
    data = get_comprehensive_attack_data(time_range)
    detailed_data = get_detailed_attacks(time_range, limit=500)

if not data or 'aggregations' not in data:
    st.error("❌ Erro ao carregar dados. Verifique a conexão com T-Pot.")
    st.stop()

agg = data['aggregations']
total_attacks = data['hits']['total']['value']
unique_ips = agg['unique_attackers']['value']
unique_countries = agg['unique_countries']['value']
unique_ports = agg['unique_ports']['value']

# ======================================================
# SEÇÃO 1: MÉTRICAS PRINCIPAIS
# ======================================================
st.header("📊 Visão Geral")

col1, col2, col3, col4, col5, col6 = st.columns(6)

with col1:
    st.metric("🎯 Total de Ataques", f"{total_attacks:,}")
with col2:
    st.metric("😈 IPs Únicos", f"{unique_ips:,}")
with col3:
    avg_per_ip = total_attacks / unique_ips if unique_ips > 0 else 0
    st.metric("📈 Média/IP", f"{avg_per_ip:.1f}")
with col4:
    st.metric("🌍 Países", f"{unique_countries:,}")
with col5:
    st.metric("🔌 Portas", f"{unique_ports:,}")
with col6:
    honeypots_active = len(agg['top_honeypots']['buckets'])
    st.metric("🍯 Honeypots", honeypots_active)

st.divider()

# ======================================================
# SEÇÃO 2: ANÁLISE GEOGRÁFICA
# ======================================================
st.header("🌍 Análise Geográfica")

# MAPA MUNDI DE BOLHAS - TEMA CYBERPUNK
st.subheader("🗺️ Mapa Mundial de Ataques")

# Opção 1: Usar agregação geo_centroid (mais eficiente)
geo_points = agg.get('geo_points', {}).get('buckets', [])

if geo_points:
    map_data = []
    for bucket in geo_points:
        country = bucket['key']
        count = bucket['doc_count']
        centroid = bucket.get('centroid', {}).get('location')
        
        if centroid:
            map_data.append({
                'country': country,
                'lat': centroid['lat'],
                'lon': centroid['lon'],
                'ataques': count,
                'percentual': f"{(count/total_attacks*100):.2f}%"
            })
    
    if map_data:
        map_df = pd.DataFrame(map_data)
        
        # Criar mapa de bolhas interativo
        fig_map = px.scatter_geo(
            map_df,
            lat='lat',
            lon='lon',
            size='ataques',
            hover_name='country',
            hover_data={
                'ataques': ':,',
                'percentual': True,
                'lat': False,
                'lon': False
            },
            color='ataques',
            color_continuous_scale=[
                [0, '#0a0e27'],      # Azul escuro profundo
                [0.2, '#1a1d3f'],    # Roxo escuro
                [0.3, '#2d1b4e'],    # Roxo médio
                [0.4, '#8b00ff'],    # Roxo neon
                [0.5, '#9d00ff'],    # Roxo brilhante
                [0.6, '#ff00ff'],    # Magenta neon
                [0.7, '#ff0080'],    # Rosa neon
                [0.85, '#ff0040'],   # Vermelho neon
                [1, '#ff0000']       # Vermelho intenso
            ],
            size_max=70,
            projection='natural earth',
            title=f'<b>🌍 MAPA GLOBAL DE ATAQUES CIBERNÉTICOS</b><br><sub>{total_attacks:,} ataques detectados | {unique_countries} países</sub>'
        )
        
        fig_map.update_layout(
            height=650,
            font=dict(
                family="Courier New, monospace",
                color="#00ff41",  # Verde matrix
                size=12
            ),
            title_font=dict(
                size=18,
                color="#00ffff"  # Ciano neon
            ),
            geo=dict(
                showframe=True,
                framecolor='#00ffff',  # Borda ciano neon
                framewidth=2,
                showcoastlines=True,
                coastlinecolor='#0066ff',  # Azul neon
                coastlinewidth=1,
                projection_type='natural earth',
                bgcolor='#0a0e27',  # Fundo azul escuro profundo
                showland=True,
                landcolor='#0d1117',  # Continentes preto azulado
                showlakes=True,
                lakecolor='#050811',  # Lagos quase pretos
                showcountries=True,
                countrycolor='#1a3a52',  # Bordas dos países azul escuro
                countrywidth=0.5,
                showocean=True,
                oceancolor='#0a0e27'  # Oceanos azul escuro profundo
            ),
            margin=dict(l=0, r=0, t=80, b=0),
            paper_bgcolor='#0d1117',  # Fundo geral escuro
            plot_bgcolor='#0d1117',
            coloraxis_colorbar=dict(
                title=dict(
                    text="<b>Ataques</b>",
                    font=dict(color="#00ffff")
                ),
                tickfont=dict(color="#00ff41"),
                bgcolor='rgba(13, 17, 23, 0.8)',
                bordercolor='#00ffff',
                borderwidth=2,
                outlinecolor='#00ffff',
                outlinewidth=1
            )
        )
        
        # Adicionar efeito de brilho nas bolhas
        fig_map.update_traces(
            marker=dict(
                line=dict(
                    width=2,
                    color='#00ffff'  # Borda ciano nas bolhas
                ),
                opacity=0.85
            )
        )
        
        st.plotly_chart(fig_map, use_container_width=True, config={'displayModeBar': False})
        
        # Estatísticas do mapa
        map_stat_col1, map_stat_col2, map_stat_col3, map_stat_col4 = st.columns(4)
        
        top_country = map_df.nlargest(1, 'ataques').iloc[0]
        
        with map_stat_col1:
            st.metric("📍 Países no Mapa", len(map_df))
        with map_stat_col2:
            st.metric("🎯 País Com Mais Ataques", top_country['country'])
        with map_stat_col3:
            st.metric("🔥 Ataques", f"{top_country['ataques']:,}")
        with map_stat_col4:
            st.metric("📊 Percentual", top_country['percentual'])

# Opção 2: Fallback usando dados detalhados (se geo_points não disponível)
elif detailed_data and detailed_data.get('hits', {}).get('hits'):
    geo_data = []
    hits = detailed_data['hits']['hits']
    
    for hit in hits:
        src = hit['_source']
        geoip = src.get('geoip', {})
        
        if geoip.get('location', {}).get('lat') and geoip.get('location', {}).get('lon'):
            geo_data.append({
                'lat': geoip['location']['lat'],
                'lon': geoip['location']['lon'],
                'country': geoip.get('country_name', 'Desconhecido'),
                'city': geoip.get('city_name', 'N/A'),
                'ip': src.get('src_ip', 'N/A')
            })
    
    if geo_data:
        geo_df = pd.DataFrame(geo_data)
        
        # Agregar por país para criar bolhas
        country_attacks = geo_df.groupby(['country', 'lat', 'lon']).size().reset_index(name='ataques')
        
        # Criar mapa
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
        
        st.plotly_chart(fig_map, use_container_width=True, config={'displayModeBar': False})
else:
    st.warning("⚠️ Não há dados de geolocalização disponíveis para este período")

st.divider()

# GRÁFICOS DETALHADOS
geo_col1, geo_col2, geo_col3 = st.columns(3)

with geo_col1:
    st.subheader("Top 15 Países")
    countries = agg['top_countries']['buckets']
    if countries:
        country_df = pd.DataFrame([
            {'País': b['key'], 'Ataques': b['doc_count'], 
             'Percentual': f"{(b['doc_count']/total_attacks*100):.1f}%"} 
            for b in countries
        ])
        fig = px.bar(country_df, x='Ataques', y='País', orientation='h',
                    color='Ataques', color_continuous_scale='Reds',
                    text='Percentual')
        fig.update_layout(height=500, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

with geo_col2:
    st.subheader("Top 15 Cidades")
    cities = agg['top_cities']['buckets']
    if cities:
        city_df = pd.DataFrame([
            {'Cidade': b['key'], 'Ataques': b['doc_count']} 
            for b in cities
        ])
        fig = px.bar(city_df, x='Ataques', y='Cidade', orientation='h',
                    color='Ataques', color_continuous_scale='Oranges')
        fig.update_layout(height=500, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

with geo_col3:
    st.subheader("Distribuição Continental")
    continents = agg.get('top_continents', {}).get('buckets', [])
    if continents:
        continent_map = {
            'AS': 'Ásia', 'EU': 'Europa', 'NA': 'América do Norte',
            'SA': 'América do Sul', 'AF': 'África', 'OC': 'Oceania', 'AN': 'Antártica'
        }
        cont_df = pd.DataFrame([
            {'Continente': continent_map.get(b['key'], b['key']), 'Ataques': b['doc_count']} 
            for b in continents
        ])
        fig = px.pie(cont_df, names='Continente', values='Ataques', hole=0.4)
        fig.update_layout(height=500)
        st.plotly_chart(fig, use_container_width=True)

st.divider()

# ======================================================
# SEÇÃO 3: ANÁLISE TEMPORAL
# ======================================================
st.header("⏰ Análise Temporal")

temp_col1, temp_col2 = st.columns([2, 1])

with temp_col1:
    st.subheader("Timeline de Ataques")
    timeline = agg['attacks_over_time']['buckets']
    if timeline:
        timeline_df = pd.DataFrame([
            {
                'Data/Hora': datetime.fromtimestamp(b['key']/1000),
                'Ataques': b['doc_count']
            } 
            for b in timeline
        ])
        fig = px.area(timeline_df, x='Data/Hora', y='Ataques',
                     color_discrete_sequence=['#ff4b4b'])
        fig.update_layout(height=350)
        st.plotly_chart(fig, use_container_width=True)

with temp_col2:
    st.subheader("Ataques por Hora do Dia")
    by_hour = agg['attacks_by_hour']['buckets']
    if by_hour:
        hour_df = pd.DataFrame([
            {'Hora': f"{int(b['key']):02d}:00", 'Ataques': b['doc_count']} 
            for b in sorted(by_hour, key=lambda x: x['key'])
        ])
        fig = px.bar(hour_df, x='Hora', y='Ataques',
                    color='Ataques', color_continuous_scale='Blues')
        fig.update_layout(height=350, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

st.divider()

# ======================================================
# SEÇÃO 4: HONEYPOTS E PORTAS
# ======================================================
st.header("🎯 Alvos e Vetores de Ataque")

target_col1, target_col2, target_col3 = st.columns(3)

with target_col1:
    st.subheader("Honeypots Atacados")
    honeypots = agg['top_honeypots']['buckets']
    if honeypots:
        hp_df = pd.DataFrame([
            {'Honeypot': b['key'], 'Ataques': b['doc_count']} 
            for b in honeypots
        ])
        fig = px.pie(hp_df, names='Honeypot', values='Ataques', hole=0.5)
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)

with target_col2:
    st.subheader("Top 20 Portas")
    ports = agg['top_ports']['buckets']
    if ports:
        port_df = pd.DataFrame([
            {'Porta': str(b['key']), 'Ataques': b['doc_count']} 
            for b in ports
        ])
        st.dataframe(port_df, use_container_width=True, hide_index=True, height=400)

with target_col3:
    st.subheader("Protocolos Usados")
    protocols = agg.get('top_protocols', {}).get('buckets', [])
    if protocols:
        proto_df = pd.DataFrame([
            {'Protocolo': b['key'], 'Ataques': b['doc_count']} 
            for b in protocols
        ])
        fig = px.bar(proto_df, x='Protocolo', y='Ataques',
                    color='Ataques', color_continuous_scale='Greens')
        fig.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)

st.divider()

# ======================================================
# SEÇÃO 5: COMANDOS E PAYLOADS
# ======================================================
st.header("💻 Análise de Comandos e Payloads")

cmd_col1, cmd_col2 = st.columns(2)

with cmd_col1:
    st.subheader("🔥 Top 30 Comandos Mais Usados")
    commands = agg.get('top_commands', {}).get('buckets', [])
    if commands:
        cmd_df = pd.DataFrame([
            {
                'Comando': b['key'][:100], 
                'Ocorrências': b['doc_count'],
                'Percentual': f"{(b['doc_count']/total_attacks*100):.2f}%"
            } 
            for b in commands if b['key']
        ])
        st.dataframe(cmd_df, use_container_width=True, hide_index=True, height=500)
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
        st.dataframe(url_df, use_container_width=True, hide_index=True, height=250)
    else:
        st.info("Nenhuma URL capturada")
    
    st.subheader("🖥️ User-Agents")
    uas = agg.get('top_user_agents', {}).get('buckets', [])
    if uas:
        ua_df = pd.DataFrame([
            {'User-Agent': b['key'][:60], 'Ocorrências': b['doc_count']} 
            for b in uas if b['key']
        ])
        st.dataframe(ua_df, use_container_width=True, hide_index=True, height=230)

st.divider()

# ======================================================
# SEÇÃO 6: CREDENCIAIS CAPTURADAS
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
        st.dataframe(user_df, use_container_width=True, hide_index=True, height=400)
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
        st.dataframe(pass_df, use_container_width=True, hide_index=True, height=400)
    else:
        st.info("Nenhuma senha capturada")

st.divider()

# ======================================================
# SEÇÃO 7: MALWARE E ARQUIVOS
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
        st.dataframe(mal_df, use_container_width=True, hide_index=True)
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
        st.dataframe(file_df, use_container_width=True, hide_index=True)
    else:
        st.info("Nenhum arquivo capturado")

st.divider()

# ======================================================
# SEÇÃO 8: TOP ATACANTES
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
        st.dataframe(ip_df, use_container_width=True, hide_index=True, height=500)

with attacker_col2:
    st.subheader("🏢 Top 15 ASN/Provedores")
    asns = agg['top_asn']['buckets']
    if asns:
        asn_df = pd.DataFrame([
            {'Provedor': b['key'], 'Ataques': b['doc_count']} 
            for b in asns
        ])
        st.dataframe(asn_df, use_container_width=True, hide_index=True, height=500)

st.divider()

# ======================================================
# SEÇÃO 9: DETALHES COMPLETOS DOS ATAQUES
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
        
        st.dataframe(filtered_df, use_container_width=True, hide_index=True, height=600)

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
