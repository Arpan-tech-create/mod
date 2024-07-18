import os
import gzip
import re
import pandas as pd
import sqlite3

def extract_gzip_files(folder_path, conn):

    file_list = os.listdir(folder_path)


    gz_files = [file for file in file_list if file.endswith('.gz')]

  
    for gz_file in gz_files:
        gz_file_path = os.path.join(folder_path, gz_file)
        log_file_path = os.path.join(folder_path, gz_file[:-3] + '.log')  

        if not os.path.exists(log_file_path):
            with gzip.open(gz_file_path, 'rb') as f_in, open(log_file_path, 'wb') as f_out:
                f_out.write(f_in.read())

            print(f'Extracted {gz_file} to {log_file_path}')

       
            parsed_df = parse_log_file(log_file_path, conn)

         
            store_data_in_db(parsed_df, conn)

    print('Log data stored in SQLite database.')

def parse_log_file(log_file_path, conn):
    latest_timestamp = pd.read_sql_query('SELECT MAX(TIMESTAMP) FROM threat', conn).iloc[0, 0]

    with open(log_file_path, 'r') as file:
        data = file.readlines()
    
    uris=r'\[uri\s+"(.*?)"\]'
    msgs=r'\[msg\s+"(.*?)"\]'
    ids=r'\[id\s*"\d+"\]'
    file=r'\[file "(.*?)"]'
    timestamp_pattern = r'\[(\d{2}/[a-zA-Z]+/\d{4}:\d{2}:\d{2}:\d{2}\s\+\d{4})\]'
    url=r'X-Real-IP:\s*([\d.]+)'
    res=r'HTTP/\d\.\d (\d+)'

    file_uri = []
    m = []   
    id = []
    file_path = []
    timestamps = []
    urls = []
    resp = []

    for line in data:
        match1 = re.search(uris, line)
        if match1:
            file_uri.append(match1.group(1))

        match2 = re.search(msgs, line)
        if match2:
            m.append(match2.group(1))

        match = re.search(ids, line)
        if match:
            id.append(match.group()[5:-2])

        match3 = re.search(file, line)
        if match3:
            file_path.append(match3.group(1))

        match4 = re.search(timestamp_pattern, line)
        if match4:
            timestamp = match4.group(1)
            if latest_timestamp is None or timestamp > latest_timestamp:
                timestamps.append(timestamp)

        match5 = re.search(url, line)
        if match5:
            urls.append(match5.group()[11:26])

        match6 = re.search(res, line)
        if match6:
            resp.append(match6.group()[8:12])



    df1 = pd.DataFrame({'TIMESTAMP': timestamps})
    df2 = pd.DataFrame({'URI':file_uri})
    df3 = pd.DataFrame({'ID':id})
    df4 = pd.DataFrame({'FILE_PATH':file_path})
    df5 = pd.DataFrame({'MESSAGE':m})
    df6 = pd.DataFrame({'IP':urls})
    df7 = pd.DataFrame({'RESPONSE':resp})
    final=pd.concat([df1,df2,df3,df4,df5,df6,df7],axis=1)
    final.dropna(inplace=True)
    return final


def store_data_in_db(final, conn):

      final.to_sql('threat', conn, if_exists='append', index=False)

folder_path = 'C:/Users/Admin/Desktop/PYTHON_FOR_GZ'
conn = sqlite3.connect('vedas.db')
extract_gzip_files(folder_path,conn)
conn.close()