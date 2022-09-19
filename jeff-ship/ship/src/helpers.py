import subprocess
import datetime
import pandas as pd
# from clusters import read_to_cluster

from tshark import *
from analysis import *
from utils import make_normal, quick_clean, generate_table



def read_pcap(filename, fields=[], display_filter="", 
              timeseries=False, strict=False):
    """ Read PCAP file into Pandas DataFrame object. 
    Uses tshark command-line tool from Wireshark.

    filename:       Name or full path of the PCAP file to read
    fields:         List of fields to include as columns
    display_filter: Additional filter to restrict frames
    strict:         Only include frames that contain all given fields 
                    (Default: false)
    timeseries:     Create DatetimeIndex from frame.time_epoch 
                    (Default: false)

    Syntax for fields and display_filter is specified in
    Wireshark's Display Filter Reference:
 
      http://www.wireshark.org/docs/dfref/
    """
    if timeseries:
        fields = ["frame.time_epoch"] + fields
        
    fieldspec = " ".join("-e %s" % f for f in fields)
    
    display_filters = fields if strict else []

    if display_filter:
        display_filters.append(display_filter)
    filterspec = "-Y '%s'" % " and ".join(f for f in display_filters)

    options = "-r %s -n -T fields -Eheader=y " % filename
    cmd = "tshark %s %s %s" % (options, filterspec, fieldspec)

    proc = subprocess.Popen(cmd, shell = True, 
                                 stdout=subprocess.PIPE)
    if timeseries:
        df = pd.read_table(proc.stdout, 
                        parse_dates=True, )
        if 'frame.time_epoch' in list(df.columns):
            df['frame.time_epoch'] = df['frame.time_epoch'].apply(lambda x: datetime.datetime.fromtimestamp(float(x)) )
        if 'frame.time' in list(df.columns):
            df['frame.time'] = pd.to_datetime(df['frame.time'])
        
    else:
        df = pd.read_table(proc.stdout)
    return df





    # plots
import plotly.express as px

def make_3dscatterplot(df_, x,y,z=None):
    fig = px.scatter_3d(df_, x = x,
                        y=y, z=z,
                        hover_data=[z],
                        color=df_[z], labels={'color': z},
                opacity = 0.8,
                size_max=30,
                
                )

    fig.update_traces(marker_size=5)

    return fig


from sklearn.cluster import DBSCAN
import numpy as np



# for our modelling
desired_columns = ['ip.src','ip.dst', 'ip.len', 'ip.flags.df', 'ip.flags.mf',
       'ip.fragment', 'ip.fragment.count', 'ip.fragments', 'ip.ttl',
       'ip.proto', 'tcp.window_size', 'tcp.ack', 'tcp.seq', 'tcp.len',
       'tcp.stream', 'tcp.urgent_pointer', 'tcp.flags', 'tcp.analysis.ack_rtt',
       'tcp.segments', 'tcp.reassembled.length', 'http.request', 'udp.port',
       'frame.time_relative', 'frame.time_delta', 'tcp.time_relative',
       'tcp.time_delta'
       ]

datagraph_cols = ['frame.time_epoch', 'ip.src','ip.dst']

def make_3d_cluster(df_):

    clusterable_embedding, clustered, labels = read_to_cluster(df_)

    return clusterable_embedding, clustered, labels


# Dimension reduction and clustering libraries
import umap.umap_ as umap
import hdbscan

modelling_columns = [ 'ip.len', 'ip.flags.df', 'ip.flags.mf',
       'ip.fragment', 'ip.fragment.count', 'ip.fragments', 'ip.ttl',
       'ip.proto', 'tcp.window_size', 'tcp.ack', 'tcp.seq', 'tcp.len',
       'tcp.stream', 'tcp.urgent_pointer', 'tcp.flags', 'tcp.analysis.ack_rtt',
       'tcp.segments', 'tcp.reassembled.length', 'http.request', 'udp.port',
       'frame.time_relative', 'frame.time_delta', 'tcp.time_relative',
       'tcp.time_delta'
       ]


# returns clusterable_embedding and clustered
def read_to_cluster(df_):

   
    if 'frame.time_epoch' in list(df_.columns):
        # temp_df = df_['frame.time_epoch', 'ip.src','ip.dst']
        df_ = df_.drop('frame.time_epoch', axis=1)

    if 'frame.time' in list(df_.columns):
        # temp_df = df_['frame.time_epoch', 'ip.src','ip.dst']
        df_ = df_.drop('frame.time', axis=1)

    # df_.drop(cols, axis=1)


    df_ = quick_clean(df_)
    
    # temp_df = df_[['ip.src', 'ip.dst']]
    df_ = df_.drop(['ip.src', 'ip.dst'], axis=1)

    df_ = df_[modelling_columns]

    # print('columns', df_.columns )

    X_norm = make_normal(df_)

    # make cluster embeddings
    clusterable_embedding = umap.UMAP(
    n_neighbors=30,
    min_dist=0.0,
    n_components=2,
    random_state=42,
    ).fit_transform(X_norm)
    
    # get labels from clsuter embeddings
    labels = hdbscan.HDBSCAN(
    min_samples=5,
    min_cluster_size=500,
    ).fit_predict(clusterable_embedding)
    
    clustered = (labels >= 0)

    return clusterable_embedding, clustered, labels


# upload helpers
import base64
import datetime
import io
from dash import html, dcc# dash_table


def parse_contents(contents, filename, date):
    print('filename: ' + filename)
    content_type, content_string = contents.split(',')
    decoded = base64.b64decode(content_string)

    flag = None
    cols = ['ip.src','ip.dst']

    try:
        if 'pcap' in filename:
            # print('entered pcap')

            # Assume that the user uploaded an excel file
            edit_fn = filename.split('.')[0]
            temp_path_pcap = '../data/temp/' + edit_fn + '.pcap' #io.BytesIO(decoded)
            temp_path_csv = '../data/temp/' + edit_fn + '.csv' #io.BytesIO(decoded)
          
            # save to pcap to disk
            open(temp_path_pcap, 'wb').write(decoded)

            # # convert pcap from disk to a csv
            # readPcaps2Csv(temp_path_pcap, temp_path_csv)
            
            # df = pd.read_csv(temp_path_csv)#desired_columns]
            df = read_pcap(temp_path_pcap, fields=desired_columns + ["frame.len"], timeseries=True)

            print(df.columns)

            if 'frame.time_epoch' in list(df.columns):
                cols = ['frame.time_epoch'] + cols
                
            if 'frame.time' in list(df.columns):
                cols = ['frame.time'] + cols


        elif 'csv' in filename:
            # Assume that the user uploaded a CSV file
            df = pd.read_csv(
                io.StringIO(decoded.decode('utf-8')))#[desired_columns]

            # if 'frame.time_epoch' not in list(df.columns) or 'frame.time' not in list(df.columns) :
            #     print('incompatible csv.')
            #     return
            #  listA = ['ip.src','ip.dst']

            res = [ele for ele in desired_columns if(ele in list(df.columns))]

            # print("Does string contain any list element : " + str(bool(res)))

            # if bool(res):
            #     print('has the desired')
                
            if 'frame.time_epoch' in list(df.columns):
                print('has the frame.time_epoch')

                # df = df.set_index('frame.time_epoch')
                flag=True
                get_set_index = 'frame.time_epoch'

            if 'frame.time' in list(df.columns):
                print('has the frame.time')
                # df = df.set_index('frame.time').reset

                flag=True
                get_set_index = 'frame.time'

            print(df.columns)
            
        elif 'xls' in filename:
            # Assume that the user uploaded an excel file
            df = pd.read_excel(io.BytesIO(decoded))

    except Exception as e:
        print(e)
        return html.Div([
            'There was an error processing this file.'
        ])

    
    if flag:
    #     # df = df[cols] + get_set_index
        cols = [get_set_index] + ['ip.src','ip.dst']

    # print('cols: ', cols)
    return html.Div([
        html.H5(filename),
       
        html.Button(id="submit-button", children="Create Graph"),
        html.Button(id="btn-nclicks-1", children="Show 3D for Anomaly Graph"),
        html.Hr(),

        generate_table(df[cols]),#stream=True),

        dcc.Store(id='stored-data', data=df.to_dict('records')),
       

       
    ])



INDEX_TO_LABEL = {0: 'sqlattack', 1: 'ddos', 2: 'probe', 3: 'benign', 4: 'bruteforce'}
LABEL_TO_INDEX= {'sqlattack': 0, 'ddos': 1, 'probe': 2, 'benign': 3, 'bruteforce': 4}

def update_3dplot(clusterable_embedding, labels):
    proj_3d = pd.DataFrame(clusterable_embedding)

    # print(proj_3d.head(2))
    formatted_labels = []

    for i in labels:
        if i in INDEX_TO_LABEL:
            formatted_labels.append(INDEX_TO_LABEL[i])
        else:
            formatted_labels.append(i)

    proj_3d['label'] = formatted_labels
            
    fig = make_3dscatterplot(df_=proj_3d, x=0,y=1,z='label')

    return fig


def update_byte_lineplot(list_data):

 
    framelen = pd.DataFrame(list_data)

    if 'frame.time' in framelen:
        framelen['frame.time'] = pd.to_datetime(framelen['frame.time'])
        framelen = framelen.set_index('frame.time')


    if 'frame.time_epoch' in list(framelen.columns):
        framelen['frame.time_epoch'] = pd.to_datetime(framelen['frame.time_epoch'])
        framelen = framelen.set_index('frame.time_epoch')
    
        
    bytes_per_second=framelen.resample("S").sum()

    fig = px.line(bytes_per_second, x=bytes_per_second.index, y="frame.len", title='Bytes Per Seconds')
    return fig



 
def read_csv(stop=False):

    df_ = read_pcap('../data/captures/pcap/test.pcap', fields=desired_columns, timeseries=True)

    print(df_.columns)
    
    return html.Div([
        # html.H5(filename),
    
        html.Button(id="submit-capture-button", children="Create Graph"),
        html.Hr(),

        generate_table(df_[datagraph_cols]),#.reset_index() ),#stream=True),

        dcc.Store(id='stored-capture-data', data=df_.to_dict('records')),
    

        
    ])



import multiprocessing, time

def capture_get_pcap():

    capturePackets('../data/captures/pcap/test', num_packets=5)

    time.sleep(15) # wait for 15 secs

    # read capture pcap
    df = read_pcap('../data/captures/pcap/test.pcap', fields=desired_columns + ["frame.len"], timeseries=True).reset_index()

    # read_csv()
    print(df.head(2))

    return html.Div([
        # html.H5(filename),
       
        html.Button(id="submit-capture-button", children="Create Graph"),
        html.Button(id="btn-nclicks-1", children="Show 3D for Anomaly Graph"),
        html.Hr(),

        generate_table(df[datagraph_cols]),#.reset_index() ),#stream=True),

        dcc.Store(id='stored-capture-data', data=df.to_dict('records')  ),

       

       
    ])

