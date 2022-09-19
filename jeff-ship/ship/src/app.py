# import imp
import dash
from dash import Dash, dcc, html, Input, Output, State, no_update, ctx
import dash_bootstrap_components as dbc
import pandas as pd

import plotly.io as pio
pio.renderers.default = "browser"

from helpers import *


#
# external_stylesheets
external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

app = dash.Dash(name=__name__, external_stylesheets=[dbc.themes.BOOTSTRAP, external_stylesheets,
dbc.themes.BOOTSTRAP], )
app.config.suppress_callback_exceptions = True






# ------------------------------------------------------------------------------
# App layout


app.layout = dbc.Container([

    html.H1(children="Network Instrusion Analytics", style={'margin:':'100px'}),
    
    # row  1
    dbc.Row([
       
         
        dbc.Col([
            dbc.Tabs([
           

            dbc.Tab([
                html.Ul([
                  html.Br(),

                    dcc.Upload(
                    id='upload-data',
                    children=html.Div([
                        'Drag and Drop or ',
                        html.A('Select Files')

                    ]),

                    style={
                        'width': '50%',
                        
                        'height': '20%',
                        'fontSize': '13px',
                        'height': '60px',
                        'lineHeight': '60px',
                        'borderWidth': '1px',
                        'borderStyle': 'dashed',
                        'borderRadius': '5px',
                        'textAlign': 'center',
                        'margin': '5px',
                        'cursor': 'pointer',
                        # 'padding': '5px',
                        
                    },
                    # Allow multiple files to be uploaded
                    multiple=True

        #  ),]
        )
         ,])], label='Load Pcap or CSV'),

            dbc.Tab([
                html.Ul([

                # same code to define the unordered list

                 html.Div([
                    html.Button(id="btn-run-capture", children="Start", style={'border-radius': '12px',
                                         'padding':'0 8px 0 8px'} ),

                    html.Button(id="btn-stop-capture", children="Stop", style={'border-radius': '12px',
                                                'margin-left':'50px','background-color':'#f44336','padding':'0 8px 0 8px'}),

                 ], style={'margin':"10px"}),

                ], style={'margin-top':"10px"}),
                ], label='Capture Live'),
           
        ]),

        html.Div(id='container-button-timestamp'),
        html.Div(id='output-datatable'),
        html.Div(id='output-capture-datatable'),


        ], width=5),

        dbc.Col(

            html.Div([  

                   html.H2( "Summary" ), 
                   html.Div(id='logs-info-analysis', style={'margin-top':'50px'}),
                   html.Div(id='logs-capture-info-analysis', style={'margin-top':'50px'}),

                   # -2
                   html.Div(id='logs-info-analysis-2', style={'margin-top':'50px'}),
                   html.Div(id='logs-capture-info-analysis-2', style={'margin-top':'50px'}),


        # ]), width=5,style={'backgroundColor':'#F1EEE9','margin-left':'150px'}) ## F1EEE9, CFD2CF
        ]), width=5,style={'backgroundColor':'#CFD2CF','margin-left':'150px'}) ## F1EEE9, CFD2CF

    ],style={'height':'600px','margin-top':'50px'}),
    # end of row 1
  
    
    # row 2

    dbc.Row([
        
            html.Div(id='output-div-head'),
            html.Div(id='output-capture-div-head'),
            # html.Div(id='output-3d-div-head'),

            dbc.Col([
                # html.Div(id='output-pca-3d')  
                html.Div(id='output-div',style={'padding':'30px 30px'}),
                html.Div(id='output-capture-div'),
                # 

            ]),

    ], style={'margin-top':"100px"} ),
    
    # end of row 2

    # row 3
    dbc.Row([
            # dbc.Col(lg=2),
            # html.Span(
            #                     children="3D Scatter"
            #                 ),           
            dbc.Col([
                html.Div(id='output-div-framelen'),
                html.Div(id='output-div-capture-framelen'),
                

            ]),

        
    ], style={'margin-top':"50px"} ),

    # end of row 3

    # html.(),

    # row 4

    dbc.Row([

            # html.H1(children="Stream with Prediction Table", style={ "textAlign": "center"}),

            dbc.Col([
                 html.Div(id='output-stream-datatable'),
                 html.Div(id='output-stream-capture-datatable'),
                 html.Div(id='output-capture-3d'),
                 html.Div(id='output-3d'),
                 
            ]),

        # 'margin-top:':'100px',
    ], style={'margin-top':"100px"} )
    # end of row 4

          

], fluid=True)

# ------------------------------------------------------------------------------



def make3d(df):
    clusterable_embedding, clustered, labels = make_3d_cluster(df)
    return dcc.Graph(figure=update_3dplot(clusterable_embedding, labels))


from analysis import make_tcp_stream_df

@app.callback(
        [ 
        
        Output('output-div-head', 'children'),
        #  Output('output-div', 'children'), 
         Output('output-div-framelen', 'children'),
         Output('output-stream-datatable', 'children'),
         Output('logs-info-analysis', 'children'),
         Output('logs-info-analysis-2', 'children'),
        #  
         ],

        Input('submit-button','n_clicks'),

        State('stored-data','data'))

def make_graphs(n, data):

    if data is None:
        return no_update

    df = pd.DataFrame(data)

    if n is None:
        return no_update
    else:

        # clusterable_embedding, clustered, labels = make_3d_cluster(df)
        # output_div =  dcc.Graph(figure=update_3dplot(clusterable_embedding, labels))

        # if not done:
        stream_df, pred_counts, src_dst_label_counts = make_tcp_stream_df(df)
        # time.sleep(5)
            # done = True
            # return [],[], stream_df, pred_counts, src_dst_label_counts

        if 'frame.len' in list(df.columns):
            output_div_framelen = dcc.Graph(figure=update_byte_lineplot(df))
            # return html.H1(children="Visualization", style={'margin-top:':'20px', "textAlign": "center"}), \
            # output_div_framelen, [],[], []
            # time.sleep(5)

        else:
            output_div_framelen = ''
            # return [], output_div_framelen,  [],[], []

        return html.Div([
            html.Hr(),

            html.H1(children="Visualization", style={'margin-top:':'500px', "textAlign": "center"}),
            
            ]), \
            output_div_framelen, stream_df, pred_counts, src_dst_label_counts
            # output_div, 



# # upload
@app.callback(Output('output-datatable', 'children'),

              Input('upload-data', 'contents'),

              State('upload-data', 'filename'),              
              State('upload-data', 'last_modified'))

def update_output(list_of_contents, list_of_names, list_of_dates):
    if list_of_contents is not None:
        children = [
            parse_contents(c, n, d) for c, n, d in
            zip(list_of_contents, list_of_names, list_of_dates)]
        return children



## capture


@app.callback(

    # [
    Output('output-capture-datatable', 'children'),
    # Output('output-capture-div', 'children')
    # ],

    Input('btn-run-capture', 'n_clicks'),
    Input('btn-stop-capture', 'n_clicks'),
    

    # State('stored-capture-data','data')
    
)
def displayClick(btn1, btn2):

    if btn1 is None:
        return no_update

    # msg = "None of the buttons have been clicked yet"
    msg=''
    
    if "btn-run-capture" == ctx.triggered_id:
        msg = "Start was most recently clicked "# + create_fn_with_time()
       
        # return capture_get_pcap(), [] #output_capture_div#read_csv())
        return capture_get_pcap()
        

    elif "btn-stop-capture" == ctx.triggered_id:

        cmd = f"killall dumpcap"
        subprocess.Popen([cmd], shell = True, stdout=subprocess.PIPE)

        msg = "EXit was sucecessful"
        return []


@app.callback(
        [
        #     
        Output('output-capture-div-head', 'children'),
        # Output('output-capture-div', 'children'),

         Output('output-div-capture-framelen', 'children'),
         Output('output-stream-capture-datatable', 'children'),

        Output('logs-capture-info-analysis', 'children'),
         Output('logs-capture-info-analysis-2', 'children'),
        ],

        Input('submit-capture-button','n_clicks'),

        State('stored-capture-data','data')
        
        )
        
def make_capture_graphs(n, data):

    print(data)
   
    if n is None:
        return no_update


    else:
        print('Issue')
        df = pd.DataFrame(data)

        print()
        print('make_capture_graphs')
        print(df.head(2))

        print('making cluster')

        output_div_capture_framelen = dcc.Graph(figure=update_byte_lineplot(df))
        stream_capture_df, pred_counts, src_dst_label_counts = make_tcp_stream_df(df)

        return html.H1(children="Visualization", style={'margin-top:':'400px', "textAlign": "center"}),\
             output_div_capture_framelen, stream_capture_df, pred_counts, src_dst_label_counts


        # return   html.Div([

        #     html.H1(children="Visualization", style={'margin-top:':'300px', "textAlign": "center"}),\
        #      output_div_capture_framelen, stream_capture_df, pred_counts, src_dst_label_counts

        # ])



# # make 3d for loaded files
@app.callback(
    Output('output-3d', 'children'),
    Input('btn-nclicks-1', 'n_clicks'),
    State('stored-data','data'),
    )


def displayClick(btn1, data):

    if btn1 is None:
        return no_update

    if data is None:
        return no_update

    
    # set to dataframe
    df = pd.DataFrame(data)

    msg = "None of the buttons have been clicked yet"
    print('clicked hm')


    if "btn-nclicks-1" == ctx.triggered_id:
        msg = "Button 1 was most recently clicked"

        clusterable_embedding, clustered, labels = make_3d_cluster(df)
        output_capture_div =  dcc.Graph(figure=update_3dplot(clusterable_embedding, labels))
    return   html.Div([

        html.Hr(),

        html.H1(children="3d Visualization", style={'margin-top:':'300px', "textAlign": "center"}),
        output_capture_div

    ])



# make 3d for capture files
@app.callback(
    Output('output-capture-3d', 'children'),
    Input('btn-nclicks-1', 'n_clicks'),
    State('stored-capture-data','data'),
    )


def displayClick2(btn1, data):

    if data is None:
        return no_update

    if btn1 is None:
        return no_update

    # set to dataframe
    df = pd.DataFrame(data)

    msg = "None of the buttons have been clicked yet"
    print('clicked hm')


    if "btn-nclicks-1" == ctx.triggered_id:
        msg = "Button 1 was most recently clicked"

        clusterable_embedding, clustered, labels = make_3d_cluster(df)
        output_capture_div =  dcc.Graph(figure=update_3dplot(clusterable_embedding, labels))
    return   html.Div([

        html.Hr(),

        html.H1(children="3d Visualization", style={'margin-top:':'300px', "textAlign": "center"}),
        output_capture_div

    ])

# btn-stop-capture


if __name__ == "__main__":


    # start_server(app)

    app.run_server(debug=True)
