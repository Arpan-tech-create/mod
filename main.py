from flask import Flask, jsonify,render_template,request
import pandas as pd
import sqlite3
from datetime import datetime


app=Flask(__name__,template_folder='templates')


conn=sqlite3.connect('vedas.db')

print ("Connected successfully")




@app.route('/')
def dash():
    conn=sqlite3.connect('vedas.db')
    cursor=conn.cursor()

 #top_ips
    cursor.execute("SELECT IP, COUNT(MESSAGE) AS MessageCount FROM threat GROUP BY IP order by MessageCount desc limit 5")
    ip_message_counts = cursor.fetchall()
    print("TOP_IPs",ip_message_counts)

    ip_data=[]
    for row in ip_message_counts:
        ip = row[0]
        message_count = row[1]
        ip_data.append({'name' : ip,'y':message_count})

   
    

    
    #top_attacks
    cursor.execute("SELECT MESSAGE, COUNT(*) AS Occurrences FROM threat WHERE RESPONSE = 403 GROUP BY MESSAGE order by Occurrences desc")
    results = cursor.fetchall()
    print(results)

    attack_data = []
   
    for row in results: 
        message = row[0]
        occurrences = row[1]
        attack_data.append({'name': message, 'y': occurrences})
    
    
    
    #top_URI
    cursor.execute("SELECT URI, COUNT(*) AS cnt FROM threat GROUP BY URI ORDER BY cnt DESC LIMIT 5")
    data = cursor.fetchall()








    #IP_counts
    query1="select count(distinct IP) as ip from threat"
    cursor.execute(query1)
    result=cursor.fetchone()
    distinct_ip=result[0]
    print(distinct_ip)



    #RESPONSE_Counts
 
    cursor.execute("select count(distinct RESPONSE) as res from threat")
    result=cursor.fetchone()
    distinct_res=result[0]
    print(distinct_res)



    #ID_Counts
    query3="select count(distinct ID) as id from threat"
    cursor.execute(query3)
    result=cursor.fetchone()
    distinct_id=result[0]
    print(distinct_id)



    #URI_Counts
    query4="select count(distinct URI) as uri from threat"
    cursor.execute(query4)
    result=cursor.fetchone()
    distinct_uri=result[0]
    print(distinct_uri)

    cursor.close()
    conn.close()
    return render_template('dashboard.html',ip1=distinct_ip,res=distinct_res,id=distinct_id,uri=distinct_uri,attack_data=attack_data,ip_data=ip_data,data=data)



@app.route('/update_ip_data', methods=['GET'])
def update_ip_data():
    selected_message = request.args.get('message')

    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()

    cursor.execute("SELECT IP, COUNT(MESSAGE) AS MessageCount FROM threat WHERE MESSAGE = ? AND RESPONSE=403 GROUP BY IP ORDER BY MessageCount DESC  limit 5", (selected_message,))
    ip_message_counts = cursor.fetchall()
    print("IP_CHANGED_BY_ATTACK_PIE",ip_message_counts)
    ip_data = []
    for row in ip_message_counts:
        ip=row[0]
        occurrence=row[1]
        ip_data.append({'name':ip,'y':occurrence})

    return jsonify(data=ip_data)

@app.route('/update_uri_data_by_attack_pie', methods=['GET'])
def update_uri_data():
    selected_message12 = request.args.get('message')

    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()

    cursor.execute("SELECT URI, COUNT(*) AS MessageCount FROM threat WHERE MESSAGE = ? AND RESPONSE=  403 GROUP BY IP ORDER BY MessageCount DESC  limit 5", (selected_message12,))
    uri_message_counts = cursor.fetchall()
    print("URI_CHANGED_BY_ATTACK_PIE",uri_message_counts)
    uri_data = []
    for row in uri_message_counts:
        ip=row[0]
        occurrence=row[1]
        uri_data.append({'name':ip,'y':occurrence})

    return jsonify(data=uri_data)


@app.route("/get_uri_chart_by_ip_pie")
def get_uri_pie_update_chart():
    ipuri=request.args.get('ip')
    conn=sqlite3.connect('vedas.db')
    cursor=conn.cursor()
    cursor.execute("select URI,count(*) as cnt from threat where IP=? group by URI order by cnt desc limit 5",(ipuri,))
    uri_results=cursor.fetchall()
    print(uri_results)
    uri_data=[]
    for row in uri_results:
        uri=row[0]
        occurrence=row[1]
        uri_data.append({'name':uri,'y':occurrence})
    return jsonify(data=uri_data)



@app.route("/get_ip_chart_by_uri_pie",methods=['GET'])
def get_ip_by_uri_pie():
    myuri=request.args.get('myuri')
    conn=sqlite3.connect('vedas.db')
    cursor=conn.cursor()
    cursor.execute("select IP,count(MESSAGE) as cnt from threat where URI=? group by IP order by cnt desc limit 5",(myuri,))
    uri_re=cursor.fetchall()
    print(uri_re)
    myuri_data=[]
    for row in uri_re:
        uri1=row[0]
        occurrence=row[1]
        myuri_data.append({'name':uri1,'y':occurrence})
    return jsonify(data=myuri_data)


@app.route("/get_attack_pie_by_uri_chart",methods=['GET'])
def get_attack_uri_data():
    uri13=request.args.get("uri13")
   
    conn=sqlite3.connect('vedas.db')
    cursor=conn.cursor()
    cursor.execute("SELECT MESSAGE, COUNT(*) AS Occurrences FROM threat WHERE RESPONSE = 403 OR URI=? GROUP BY MESSAGE order by Occurrences desc limit 5 ",(uri13,))
    results3=cursor.fetchall()
    print(results3)
    attack_data_by_uri = []
    for row in results3:
        message=row[0]
        occurrences=row[1]
        attack_data_by_uri.append({'name':message,'y':occurrences})

    return jsonify(data=attack_data_by_uri)



@app.route('/get_attack_data/<ip12>')
def get_attack_data(ip12):
   

    
    conn=sqlite3.connect('vedas.db')
    cursor=conn.cursor()
    cursor.execute("SELECT MESSAGE, COUNT(*) AS Occurrences FROM threat WHERE RESPONSE = 403 OR IP=? GROUP BY MESSAGE order by Occurrences desc limit 5 ",(ip12,))
    results = cursor.fetchall()
    print(results)
    attack_data = []
    for row in results:
        message = row[0]
        occurrences = row[1]
        attack_data.append({'name': message, 'y': occurrences})
   
    return jsonify(attack_data)


   


@app.route("/update_response_ip_id_count_by_uri")
def update_response_count():
    uri = request.args.get('uri')
    count_type = request.args.get('type') 

    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()

    if count_type == 'ip':
        cursor.execute("SELECT COUNT(DISTINCT IP) AS count FROM threat WHERE URI = ?", (uri,))
    elif count_type == 'response':
        cursor.execute("SELECT COUNT(DISTINCT RESPONSE) AS count FROM threat WHERE URI = ?", (uri,))
    elif count_type == 'id':
        cursor.execute("SELECT COUNT(DISTINCT ID) AS count FROM threat WHERE URI = ?", (uri,))

    result = cursor.fetchone()
    distinct_count = result[0]

    cursor.close()
    conn.close()
    return str(distinct_count)


@app.route("/update_response_id_uri_count_by_ip_pie")
def update_response_count_by_IP_PIE():
    ip = request.args.get('ip')
    count_type = request.args.get('type') 

    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()

    if count_type == 'uri':
        cursor.execute("SELECT COUNT(DISTINCT URI) AS count FROM threat WHERE IP = ?", (ip,))
    elif count_type == 'response':
        cursor.execute("SELECT COUNT(DISTINCT RESPONSE) AS count FROM threat WHERE IP = ?", (ip,))
    elif count_type == 'id':
        cursor.execute("SELECT COUNT(DISTINCT ID) AS count FROM threat WHERE IP = ?", (ip,))

    result1 = cursor.fetchone()
    distinct_count1 = result1[0]

    cursor.close()
    conn.close()
    return str(distinct_count1)


@app.route("/update_ip_id_uri_by_attack_pie")
def chart_updates_by_attack_pie():

    msg=request.args.get('msg')
    count_type=request.args.get('type')
    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()

    if count_type=='ip':
        cursor.execute("select COUNT(distinct IP) as ip from threat WHERE RESPONSE=403 AND MESSAGE=?",(msg,))
    elif count_type=='id':
        cursor.execute("select count(distinct ID) as id from threat WHERE RESPONSE=403 AND MESSAGE=?",(msg,))
    elif count_type=='uri':
        cursor.execute("select count(distinct URI) as uri from threat WHERE RESPONSE=403 AND MESSAGE=?",(msg,))

    results3=cursor.fetchone()
    dist_cnt=results3[0]
    cursor.close()
    conn.close()
    return str(dist_cnt)
    




@app.route('/get_dist_ip_for_403_top_attacks',methods=['GET'])
def dist_ip_attack():
    selected_message=request.args.get('message')
    conn=sqlite3.connect('vedas.db')
    cursor=conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT IP) AS ip FROM threat WHERE MESSAGE=? AND RESPONSE=403", (selected_message,))
    result = cursor.fetchone()
    distinct_ip_attack =result[0]
    print("IP_ATTACK",distinct_ip_attack)

    cursor.close()
    conn.close()

    return str(distinct_ip_attack)



@app.route('/get_dist_id_for_403_top_attacks',methods=['GET'])
def dist_id_attack():
    selected_message=request.args.get('message')
    conn=sqlite3.connect('vedas.db')
    cursor=conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT ID) AS id FROM threat WHERE MESSAGE=? AND RESPONSE=403", (selected_message,))
    result = cursor.fetchone()
    distinct_id_attack =result[0]
    print("ID_ATTACK",distinct_id_attack)

    cursor.close()
    conn.close()

    return str(distinct_id_attack)


@app.route('/get_dist_uri_for_403_top_attacks',methods=['GET'])
def dist_uri_attack():
    selected_message=request.args.get('message')
    conn=sqlite3.connect('vedas.db')
    cursor=conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT URI) AS id FROM threat WHERE MESSAGE=? AND RESPONSE=403", (selected_message,))
    result = cursor.fetchone()
    distinct_URI_attack =result[0]
    print("URI_ATTACK",distinct_URI_attack)

    cursor.close()
    conn.close()

    return str(distinct_URI_attack)








#for date_chart(Daily Occurences)
@app.route('/data')
def get_data():
    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()

    
    cursor.execute("SELECT substr(TIMESTAMP, 1, 11), COUNT(*) FROM threat GROUP BY substr(TIMESTAMP, 1, 11)")

    data = cursor.fetchall()
    print(data)

    cursor.close()
    conn.close()

    return {'data': data}







@app.route('/filtered_data', methods=['GET'])
def get_filtered_data():
    selected_ip = request.args.get('selected_ip')
    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()
    cursor.execute("SELECT substr(TIMESTAMP, 1, 11), COUNT(*) FROM threat WHERE IP = ? GROUP BY substr(TIMESTAMP, 1, 11)", (selected_ip,))
    data = cursor.fetchall()
    print("MY_FILTER_",data)

    cursor.close()
    conn.close()

    return jsonify({'data': data})


@app.route('/filtered_data_by_uri',methods=['GET'])
def get_filter_data_by_my_uri():
    select_uri=request.args.get('select_uri')
    conn=sqlite3.connect('vedas.db')
    cursor=conn.cursor()
    cursor.execute("SELECT substr(TIMESTAMP, 1, 11), COUNT(*) FROM threat WHERE URI = ? GROUP BY substr(TIMESTAMP, 1, 11)", (select_uri,))
    data=cursor.fetchall()
    print("URI_BAR_NEW_CHART",data)

    cursor.close()
    conn.close()

    return jsonify({'data':data})


@app.route('/filtered_data_by_attack',methods=['GET'])
def get_filter_data_by_my_attack():
    select_attack=request.args.get('select_attack')
    conn=sqlite3.connect('vedas.db')
    cursor=conn.cursor()
    cursor.execute("SELECT substr(TIMESTAMP, 1, 11), COUNT(*) FROM threat WHERE MESSAGE = ? AND RESPONSE=403 GROUP BY substr(TIMESTAMP, 1, 11)", (select_attack,))
    data=cursor.fetchall()
    print("ATTACK_BAR_NEW_CHART",data)

    cursor.close()
    conn.close()

    return jsonify({'data':data})




@app.route('/distinct_ip_count_for_date', methods=['GET'])
def get_distinct_ip_count():
    date = request.args.get('date')
    
    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT IP) AS distinct_ip FROM threat WHERE substr(TIMESTAMP, 1, 11) = ?", (date,))
    data = cursor.fetchone()
    ip1 = data[0]
    
    print("DISTINCT_IP_FOR_DATE",ip1)
   
    cursor.close()
    conn.close()
    
    return {'ip1': ip1}

@app.route('/distinct_response_count_for_date', methods=['GET'])
def get_distinct_res_count():
    date = request.args.get('date')
    
    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT RESPONSE) AS distinct_res FROM threat WHERE substr(TIMESTAMP, 1, 11) = ?", (date,))
    data = cursor.fetchone()
    res = data[0]
    print("DISTINCT_RES_FOR_DATE",res)
    cursor.close()
    conn.close()
    
    return {'res': res}



@app.route('/distinct_id_count_for_date', methods=['GET'])
def get_distinct_id_count():
    date = request.args.get('date')
    
    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT ID) AS distinct_id FROM threat WHERE substr(TIMESTAMP, 1, 11) = ?", (date,))
    data = cursor.fetchone()
    id = data[0]
    print("DISTINCT_ID_FOR_DATE",id)
    cursor.close()
    conn.close()
    
    return {'id': id}


@app.route('/distinct_uri_count_for_date', methods=['GET'])
def get_distinct_uri_count():
    date = request.args.get('date')
    
    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT URI) AS distinct_id FROM threat WHERE substr(TIMESTAMP, 1, 11) = ?", (date,))
    data = cursor.fetchone()
    uri = data[0]
    print("DISTINCT_URI_FOR_DATE",uri)
    cursor.close()
    conn.close()
    
    return {'uri': uri}


#for hourly_chart
@app.route('/hourly_data')
def get_hourly_data():
    date = request.args.get('date')
    URI = request.args.get('URI')
    IP = request.args.get('IP')
    MESSAGE = request.args.get('MESSAGE')
    RESPONSE = request.args.get('RESPONSE')

    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()
    stmt = "SELECT substr(TIMESTAMP, 13, 2), COUNT(*) FROM threat WHERE substr(TIMESTAMP, 1, 11)  = '" + date + "' "
    if URI is not None:
        stmt += " and URI = '" + URI + "'"
    
    if IP is not None:
        stmt += " and IP = '" + IP + "'"

    if MESSAGE is not None:
        stmt +="  and MESSAGE = '" + MESSAGE + "'"
    if RESPONSE  is not None:
        stmt +="  and RESPONSE  = '" + RESPONSE + "'"
    stmt += " group by substr(TIMESTAMP, 13, 2) "
    
    print(stmt)
    cursor.execute(stmt)
    #cursor.execute("SELECT subt WHERE substr(TIMESTAMP, 1, 11) = ? GROUP BY substr(TIMESTAMP, 13, 2)", (date,))
  
    data = cursor.fetchall()
    print(data)


    cursor.close()
    conn.close()
    

    return {'data': data}

@app.route('/filter_by_attack_hourly_bar',methods=['GET'])
def get_data_for_date_bar_attack():
    date=request.args.get('date')

    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()

    
    cursor.execute("SELECT substr(TIMESTAMP, 13, 2), COUNT(*) as cnt  FROM threat where RESPONSE=403 AND MESSAGE='Inbound Anomaly Score Exceeded (Total Score: 5)' AND substr(TIMESTAMP, 1, 11)=? GROUP BY substr(TIMESTAMP, 13, 2)",(date,))

    data = cursor.fetchall()
    print("MY_HOURS",data)

    cursor.close()
    conn.close()

    return {'data': data}


def convert_timestamp(timestamp):
  
    dt = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S +%f')
    return dt.strftime('%Y-%m-%d %H:%M:%S')



def get_filtered_results(from_date_obj, to_date_obj, selected_responses=None):
    conn = sqlite3.connect('vedas.db')
    cursor = conn.cursor()

    if selected_responses:
        if '20x' in selected_responses:
            selected_responses.extend(['200', '203'])
        if '30x' in selected_responses:
            selected_responses.extend(['302', '304'])
        
        if '40x' in selected_responses:
            selected_responses.extend(['400', '403'])
         
        if '50x' in selected_responses:
            selected_responses.extend(['500', '502'])

        cursor.execute('SELECT * FROM threat WHERE RESPONSE IN ({})'.format(','.join('?' * len(selected_responses))), selected_responses)
    else:
        cursor.execute("SELECT * FROM threat")

    rows = cursor.fetchall()

    results = []
    for row in rows:
        timestamp_str = row[0]
        timestamp = convert_timestamp(timestamp_str)
        timestamp_obj = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S').date()
        
        if selected_responses:
            if from_date_obj <= timestamp_obj <= to_date_obj:
                results.append(row)
        else:
            row_date = timestamp_obj  
            if from_date_obj <= row_date <= to_date_obj:
                results.append(row)

    cursor.close()
    conn.close()

    return results


@app.route('/tables',methods=['GET','POST'])
def tab():
  conn = sqlite3.connect('vedas.db')
  cur = conn.cursor()
    
  if request.method == 'POST':
        selected_responses = request.form.getlist('response')

        from_date = request.form['from_date']
        to_date = request.form['to_date']

        if from_date and to_date:
            from_date_obj = datetime.strptime(from_date, '%Y-%m-%d').date()
            to_date_obj = datetime.strptime(to_date, '%Y-%m-%d').date()
        else:
            from_date_obj = datetime.min.date()
            to_date_obj = datetime.max.date()

        data = get_filtered_results(from_date_obj, to_date_obj, selected_responses)

  else:
        cur.execute('SELECT * FROM threat')
        data = cur.fetchall()
  conn.close()

  return render_template('tables.html', data=data)

if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0' , port=5000)

