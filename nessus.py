#!/usr/bin/python3
#-*- coding:utf-8 -*-
#author:Jean
#Blog:http://sq1map.com/
#GitHub:https://github.com/jeansgit
import csv
import sys
import pandas as pd
import sqlite3
import time
start=time.time()
print("开始转中文")
df1=pd.read_csv(sys.argv[1])
conn = sqlite3.connect('nessusvul.db')
c = conn.cursor()
res=[]
critical=0
high=0
medium=0
low=0
criticalvul=[]
highvul=[]
pluginoutput=[]
host=[]

for index,row2 in df1.iterrows():
    pluginid=row2['Plugin ID']
    if pluginid==19506:
        pluginoutput.append(row2['Plugin Output'])
    cursor = c.execute("SELECT id, name,description, solution,synopsis  from nessuschinese where id=%d"%pluginid)
    if row2['Host'] not in host:
        host.append(row2['Host'])
    therisk=row2['Risk']
    if therisk=='Critical':
        critical+=1
        criticalvul.append(row2['Name'])
    elif therisk=='High':
        high+=1
        highvul.append(row2['Name'])
    elif therisk=='Medium':
        medium+=1
        #mediumvul.append(row2['Name'])
    elif therisk=='Low':
        low+=1
        #lowvul.append(row2['Name'])
    row = cursor.fetchall()
    if row:
        for nessus in row:
            #print(nessus)
            row2['Plugin ID']=nessus[0]
            row2['Name']=nessus[1]
            row2['Description']=nessus[2]
            row2['Solution']=nessus[3]
            row2['Synopsis']=nessus[4]
            row2['See Also']=row2['See Also']
            row2['Protocol']=row2['Protocol']
            row2['Risk']=row2['Risk']
            row2['CVSS v2.0 Base Score']=row2['CVSS v2.0 Base Score']
            row2['CVE']=row2['CVE']
            row2['Port']=row2['Port']
            row2['Plugin Output']=row2['Plugin Output']
            row2['Host']=row2['Host']
            #print(row2)
            res.append(row2)
        print("匹配到的Plugin ID:%s,漏洞名称:%s"%(pluginid,row2['Name']))
    else:
        res.append(row2)
        print("未匹配到的Plugin ID:%s,漏洞名称:%s"%(pluginid,row2['Name']))
conn.close()
writer=pd.ExcelWriter(sys.argv[2])

df2=pd.DataFrame(res)
listsort = ['Critical', 'High', 'Medium','Low','None']
df2['Risk'] = df2['Risk'].astype('category').cat.set_categories(listsort)
df_sortes=df2.sort_values(by=['Risk'], ascending=True)
df3=pd.DataFrame(df_sortes)
df3.to_excel(writer,sheet_name='漏洞详情',index=False)
writer.save()
writer.close()
end=time.time()
print("运行时间:%s s"%(end-start))