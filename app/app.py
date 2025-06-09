import os
import pandas as pd
import numpy as np
import dash
from dash import dcc, html, Input, Output
import plotly.express as px

carpeta = 'TrafficLabelling_Limpia'

MAX_ROWS_LOAD = 100000
dfs = []
for archivo in os.listdir(carpeta):
    if archivo.endswith('.csv'):
        ruta_archivo = os.path.join(carpeta, archivo)
        df_temp = pd.read_csv(ruta_archivo)
        dfs.append(df_temp)
df = pd.concat(dfs, ignore_index=True)

if len(df) > MAX_ROWS_LOAD:
    df = df.sample(MAX_ROWS_LOAD, random_state=42).reset_index(drop=True)

df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')

if 'ProtocolName' not in df.columns:
    protocolo_map = {
        6: 'TCP',
        17: 'UDP',
        1: 'ICMP',
        0: 'HOPOPT',
        2: 'IGMP',
        58: 'ICMPv6',
    }
    df['ProtocolName'] = df['Protocol'].map(protocolo_map).fillna('Otro')

protocol_options = [{'label': p, 'value': p} for p in sorted(df['ProtocolName'].unique())]
ips_maliciosas = df.loc[df['Label'] != 'BENIGN', 'Source IP'].dropna().unique()
ip_options = [{'label': ip, 'value': ip} for ip in sorted(ips_maliciosas)]

app = dash.Dash(__name__)
app.title = "Dashboard CICIDS2017 - Visual Analytics"

app.layout = html.Div(style={'font-family': 'Arial, sans-serif', 'max-width': '1200px', 'margin': 'auto'}, children=[
    html.H1("Dashboard CICIDS2017 - Visual Analytics", style={'textAlign': 'center', 'marginTop': 20, 'marginBottom': 30}),

    html.Div(id='ip-label-summary', style={
        'display': 'flex', 'justifyContent': 'center', 'gap': '20px', 'marginBottom': '20px'
    }),

    html.Div([
        html.Div([
            html.Label("Filtrar por protocolo:"),
            dcc.Dropdown(id='protocol-filter', options=protocol_options, value=None, placeholder="Selecciona protocolo", clearable=True),
        ], style={'width': '30%', 'display': 'inline-block', 'padding': '10px'}),

        html.Div([
            html.Label("Rango duración del flujo (Flow Duration):"),
            dcc.RangeSlider(
                id='flow-duration-slider',
                min=df['Flow Duration'].min(),
                max=df['Flow Duration'].max(),
                step=10000,
                value=[df['Flow Duration'].min(), df['Flow Duration'].max()],
                tooltip={"placement": "bottom", "always_visible": True}
            ),
        ], style={'width': '90%', 'padding': '20px 10px 40px 10px'}),
    ]),

    html.Div([
        html.Div([
            html.Label("Seleccionar IP (maliciosa):"),
            dcc.Dropdown(id='ip-filter', options=ip_options, value=None, placeholder="Selecciona IP maliciosa", clearable=True),
        ], style={'width': '40%', 'padding': '10px'}),
    ]),

    html.Div([
        dcc.Graph(id='scatter-plot'),
        dcc.Graph(id='bar-protocol'),
        dcc.Graph(id='time-series'),
        dcc.Graph(id='label-distribution'),
        dcc.Graph(id='ip-timeline'),
        dcc.Graph(id='heatmap-hourly'),
        dcc.Graph(id='box-duration'),
        dcc.Graph(id='hist-protocol-label'),
        dcc.Graph(id='multi-line-hour-label'),
        dcc.Graph(id='correlation-matrix')
    ])
])

@app.callback(
    [Output('scatter-plot', 'figure'),
     Output('bar-protocol', 'figure'),
     Output('time-series', 'figure'),
     Output('label-distribution', 'figure'),
     Output('ip-timeline', 'figure'),
     Output('heatmap-hourly', 'figure'),
     Output('box-duration', 'figure'),
     Output('hist-protocol-label', 'figure'),
     Output('multi-line-hour-label', 'figure'),
     Output('correlation-matrix', 'figure'),
     Output('ip-label-summary', 'children')],
    [Input('protocol-filter', 'value'),
     Input('flow-duration-slider', 'value'),
     Input('ip-filter', 'value')]
)
def update_graphs(selected_protocol, flow_duration_range, selected_ip):
    dff = df.copy()

    if selected_ip:
        dff = dff[dff['Source IP'] == selected_ip]

    dff = dff[
        (dff['Flow Duration'] >= flow_duration_range[0]) &
        (dff['Flow Duration'] <= flow_duration_range[1])
    ]

    if selected_protocol:
        dff = dff[dff['ProtocolName'] == selected_protocol]

    MAX_ROWS_CALLBACK = 5000
    if len(dff) > MAX_ROWS_CALLBACK:
        dff = dff.sample(MAX_ROWS_CALLBACK, random_state=42)

    dff = dff.copy()

    if selected_ip:
        resumen = dff['Label'].value_counts()
        children = []
        etiquetas_importantes = ['BENIGN', 'Bot', 'DDoS', 'PortScan', 'DoS', 'Infiltration']
        for etiqueta in etiquetas_importantes:
            count = resumen.get(etiqueta, 0)
            color = 'green' if etiqueta == 'BENIGN' else 'red'
            children.append(html.Div([
                html.H4(f"{etiqueta}: {count}"),
            ], style={
                'padding': '10px 20px',
                'border': f'2px solid {color}',
                'borderRadius': '10px',
                'minWidth': '100px',
                'textAlign': 'center',
                'color': color,
                'fontWeight': 'bold',
                'backgroundColor': '#f9f9f9'
            }))
    else:
        children = [html.P("Selecciona una IP maliciosa para ver el resumen de etiquetas.", style={'textAlign': 'center', 'fontStyle': 'italic', 'color': 'gray'})]

    fig_scatter = px.scatter(
        dff, x='Flow Duration', y='Total Fwd Packets',
        color='ProtocolName',
        title='Flow Duration vs Total Fwd Packets',
        hover_data=['Label', 'Source IP', 'Destination IP'],
        template='plotly_white'
    )

    protocol_counts = dff['ProtocolName'].value_counts().reset_index()
    protocol_counts.columns = ['Protocol', 'Count']
    fig_bar = px.bar(protocol_counts, x='Protocol', y='Count', title='Conteo de protocolos filtrados', template='plotly_white')

    dff.loc[:, 'Hour'] = dff['Timestamp'].dt.hour
    hourly_counts = dff.groupby('Hour').size().reset_index(name='Counts')
    fig_time = px.line(hourly_counts, x='Hour', y='Counts', title='Número de conexiones por hora', template='plotly_white')
    fig_time.update_layout(xaxis=dict(dtick=1), yaxis_title="Número de conexiones", xaxis_title="Hora del día")

    label_counts = df['Label'].value_counts().reset_index()
    label_counts.columns = ['Label', 'Count']
    fig_label = px.pie(label_counts, values='Count', names='Label', title='Distribución de etiquetas', template='plotly_white')

    if selected_ip:
        dff_ip = dff[dff['Source IP'] == selected_ip].copy()
        dff_ip = dff_ip.sort_values('Timestamp')
        fig_timeline = px.scatter(
            dff_ip, x='Timestamp', y='Flow Duration',
            color='Label', title=f'Línea de tiempo de eventos para IP: {selected_ip}',
            hover_data=['ProtocolName', 'Total Fwd Packets', 'Destination IP'],
            template='plotly_white'
        )
    else:
        fig_timeline = px.scatter(title="Selecciona una IP maliciosa para ver su línea de tiempo")

    if selected_ip:
        dff_ip = dff[dff['Source IP'] == selected_ip].copy()
        dff_ip['Hour'] = dff_ip['Timestamp'].dt.hour
        heatmap_data = dff_ip.groupby(['Hour', 'Label']).size().reset_index(name='Counts')
        fig_heatmap = px.density_heatmap(
            heatmap_data, x='Hour', y='Label', z='Counts', histfunc='sum',
            title=f'Heatmap horario de conexiones para IP: {selected_ip}', template='plotly_white',
            color_continuous_scale='Plasma'
        )
        fig_heatmap.update_layout(xaxis=dict(dtick=1, title='Hora del día'), yaxis=dict(title='Etiqueta (Label)'), coloraxis_colorbar=dict(title='Número de conexiones'))
    else:
        fig_heatmap = px.density_heatmap(title="Selecciona una IP maliciosa para ver el heatmap horario", template='plotly_white')

    fig_box_duration = px.box(dff, x='Label', y='Flow Duration', title='Distribución de Duración del Flujo por Etiqueta', points="all", template='plotly_white')

    fig_hist_protocol_label = px.histogram(dff, x='ProtocolName', color='Label', barmode='stack', title='Conteo de Protocolos por Etiqueta', template='plotly_white')

    hourly_label_counts = dff.groupby(['Hour', 'Label']).size().reset_index(name='Counts')
    fig_multi_line = px.line(hourly_label_counts, x='Hour', y='Counts', color='Label', title='Número de conexiones por hora y etiqueta', template='plotly_white')
    fig_multi_line.update_layout(xaxis=dict(dtick=1))

    corr = dff.select_dtypes(include=np.number).corr()
    fig_corr = px.imshow(corr, text_auto=True, title='Matriz de Correlación entre Variables Numéricas', color_continuous_scale='RdBu_r', zmin=-1, zmax=1, template='plotly_white')

    return fig_scatter, fig_bar, fig_time, fig_label, fig_timeline, fig_heatmap, fig_box_duration, fig_hist_protocol_label, fig_multi_line, fig_corr, children

if __name__ == '__main__':
    app.run(debug=True)
