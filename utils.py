# sklearn skill
from sklearn.preprocessing import StandardScaler
from sklearn import preprocessing as prep
import pandas as pd


# ------------------------------------------------------------------------------
# Reusable Components

# custom code
def make_normal(df_):

    scaler = StandardScaler()
    X_s = scaler.fit_transform(df_)
    return pd.DataFrame(prep.normalize(X_s))


def drop_these(df_, items):
    return df_.drop(items, axis=1)



# quick clean`

# quick function to ditch any hex value
def check_hex(df_):
    bye = []
    for i in df_:
        if str(i).isdecimal():
            bye.append(0)
        else:
            bye.append(int(i, 0))
    return bye


def quick_clean(df_):

    print('inside quick_clean')

    if 'frame.time_epoch' in list(df_.columns):
        temp_df = df_[['frame.time_epoch', 'ip.src','ip.dst']]
        df_ = df_.drop('frame.time_epoch', axis=1)

    if 'frame.time' in list(df_.columns):
        temp_df = df_[['frame.time', 'ip.src','ip.dst']]
        df_ = df_.drop('frame.time', axis=1)
    
    else:
        print(df_.head(2))
        temp_df = df_[['ip.src', 'ip.dst']]
        print(df_.columns)
        df_ = df_.drop(['ip.src', 'ip.dst'], axis=1)



    for c in df_.columns:
        df_[c] = pd.to_numeric(df_[c], errors='coerce')
    

    df_ = df_.fillna(0)

    try:
        
        df_['tcp.flags'] = check_hex(df_['tcp.flags'])
        
        # df_.fillna(0, inplace=True)

        
        # df_.dropna(how='all', axis=1, inplace=True)
    except:
        pass

    df_ = pd.concat([temp_df, df_])

    df_ = df_.fillna(0)


    
    return df_



from dash import dash_table

def generate_table(dataframe):
    
        
    return dash_table.DataTable(dataframe.to_dict('records'),[{"name": i, "id": i} for i in dataframe.columns], 
    page_size=10, 
    # style_cell={'textAlign': 'left'},
    #   style_table={
    #     'textOverflow': 'ellipsis',
    # }
                style_cell={'textAlign': 'left'},
            style_table={
                'textOverflow': 'ellipsis',
            }
    )
    # dbc.Alert(id='tbl_out'))


from datetime import datetime

def create_fn_with_time():
    return datetime.now().strftime("%Y-%m-%d-%I-%M-%S-%p")





# plots
