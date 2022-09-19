import pandas as pd
from dash import dash_table, html

from utils import make_normal, quick_clean, generate_table



modelling_columns = [ 'ip.len', 'ip.flags.df', 'ip.flags.mf',
       'ip.fragment', 'ip.fragment.count', 'ip.fragments', 'ip.ttl',
       'ip.proto', 'tcp.window_size', 'tcp.ack', 'tcp.seq', 'tcp.len',
       'tcp.stream', 'tcp.urgent_pointer', 'tcp.flags', 'tcp.analysis.ack_rtt',
       'tcp.segments', 'tcp.reassembled.length', 'http.request', 'udp.port',
       'frame.time_relative', 'frame.time_delta', 'tcp.time_relative',
       'tcp.time_delta'
       ]

# hold_for_concat = ['frame.time_epoch', 'tcp.stream', 'ip.src', 'ip.dst', 'tcp.len']

from sklearn.decomposition import PCA

# TCP stream to analyse
def make_tcp_stream_df(ts):


    hold_for_concat = ['tcp.stream', 'ip.src', 'ip.dst', 'tcp.len']

    had = None
    
    # temp_df = ts[hold_for_concat]

    # if bool(res):
    if 'frame.time_epoch' in list(ts.columns):
        print('has the frame.time_epoch')
        had = 'frame.time_epoch'
        # hold_for_concat += [had]

        temp_df = ts['frame.time_epoch']# + had


    if 'frame.time' in list(ts.columns):
        print('has the frame.time')
        had = 'frame.time'
        # hold_for_concat += [had]

        # # get stream
        # # stream = ts
        temp_df = ts['frame.time']#+ had

    # else:
    #     return 'Cannot work with this.'
    #     temp_df = ts[hold_for_concat]
        # print('-------')
  
    print(ts.head(2))
    print('-------')
    print('temp_df')
    print(temp_df)
    print('-------')

    ts = quick_clean(ts)
    
    # ts.drop(hold_for_concat, axis=1, inplace=True)
        # ts.drop(hold_for_concat, axis=1, inplace=True)
    print('ts')
    print(ts.columns)
    print(ts.head(2))

        # ts.set_index('frame.time_epoch', inplace=True)

    # get stream
    if had == 'frame.time_epoch' or had == 'frame.time':
        # ts[had] = pd.to_datetime(ts[had])
        ts[had] = pd.to_datetime(temp_df)
        

        stream = ts
        # temp_df[had] = pd.to_datetime(temp_df[had])
        print('-------')
        # print(temp_df)
        # stream = pd.concat([temp_df, ts], axis=1)
    else:
        stream = ts
    #     stream = pd.concat([temp_df, ts], axis=1)
        

    print('-------')
    print(stream.head(2))
    print('-------')

    # stream = stream.fillna(0)# inplace=True)

    print('-------')
    # print(stream.head(2))
    print('-------')
    print('-------')
    # print(stream.iloc[0]["ip.src"])
    print('------------------------')
    # stream=ts[ts["tcp.stream"] == 10] # pick stream number 10

    stream["type"] = stream.apply(lambda x: "client" if x["ip.src"] == stream.iloc[0]["ip.src"] else "server", axis=1)

    # return stream.to_string()
    X_norm = make_normal(ts[modelling_columns])

    f_df =pd.DataFrame()
    
    pca = PCA(n_components=3)
    pca_result = pca.fit_transform(X_norm.values)
    f_df['pca-one'] = pca_result[:,0]
    f_df['pca-two'] = pca_result[:,1] 
    f_df['pca-three'] = pca_result[:,2]
    # print('Explained variation per principal component: {}'.format(pca.explained_variance_ratio_))


    # make prediction
    preds = list()
    for i in f_df.values:
    # for i in X_norm.values:
        preds.append(make_prediction(i))

    stream['prediction'] = preds

    if had == 'frame.time_epoch' or had == 'frame.time':
        print('had ->', had)
        stream = stream[[had,'ip.src', 'ip.dst','type','prediction']]
    else:
        stream = stream[['ip.src', 'ip.dst','type','prediction']]

    print('-------')
    print(stream.head(2))
    print('-------')

    pred_counts, src_dst_label_counts = make_stream_analysis(stream)

    return html.Div([

            html.H1(children="Stream with Prediction Table", style={ "textAlign": "center"}),
            generate_table(stream),

    ]), html.Div([
        html.H6(['Predictions']),
        generate_table(pred_counts),
            
    ]), html.Div([
        html.H6(['IP Counts']), generate_table(src_dst_label_counts)])


def make_stream_analysis(df_):
    
    pred_counts = pd.DataFrame(df_.prediction.value_counts()).reset_index()
    pred_counts.columns = ['label', 'counts']

    src_dst_label_counts = pd.DataFrame((df_[['ip.src','ip.dst','prediction']].value_counts()[:10])).reset_index()
    src_dst_label_counts.columns = ['ip.src','ip.dst','prediction', 'counts']

    return pred_counts, src_dst_label_counts

    
        
# make prediction using randomforest model

import joblib
from sklearn.ensemble import RandomForestClassifier
import numpy as np


# GLOBAL DICTIONARY
INDEX_TO_LABEL = {0: 'sqlattack', 1: 'ddos', 2: 'probe', 3: 'benign', 4: 'bruteforce'}
LABEL_TO_INDEX= {'sqlattack': 0, 'ddos': 1, 'probe': 2, 'benign': 3, 'bruteforce': 4}


# custom function
def loop_each(t):
    d = []
    for i in t:
        d.append(INDEX_TO_LABEL[i])
    return ', '.join(d)



randclf = joblib.load('../data/weights/randclf_model_01.pkl')

# randclf = RandomForestClassifier(random_state=42)

def make_prediction(x):

    randclf_predictions = randclf.predict([x])
    result = np.unique(randclf_predictions)
    return INDEX_TO_LABEL[result.item()]
    # if len(result) > 1:
    #     print(f'Result are `{loop_each(result)}`')
    # else:
        # print(f'Result, this is `{INDEX_TO_LABEL[result.item()]}`')

