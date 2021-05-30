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
    if cursor:
        for nessus in cursor:
            #print(nessus)
            row2['Plugin ID']=nessus[0]
            row2['Name']=nessus[1]
            row2['Description']=nessus[2]
            row2['Solution']=nessus[3]
            row2['Synopsis']=nessus[4]
            row2['See Also']=row2['See Also']
            row2['Protocol']=row2['Protocol']
            row2['Risk']=row2['Risk']
            row2['CVSS']=row2['CVSS']
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
vulrisk={"Critical":critical,"High":high,"Medium":medium,"Low":low}
#print(vulrisk)
df7=pd.DataFrame(pluginoutput,index=[0])
df7.columns=(['扫描信息'])
df7.to_excel(writer,sheet_name="扫描信息",index=False)
df8=pd.DataFrame(host,index=[0])
df8.columns=(['扫描资产'])
df8.to_excel(writer,sheet_name="扫描资产",index=False)
df4=pd.DataFrame(vulrisk,index=[0])
df4.to_excel(writer,sheet_name="漏洞统计",index=False)

crivul=[]
for vulname in criticalvul:
    if [vulname,criticalvul.count(vulname)] not in crivul:
        crivul.append([vulname,criticalvul.count(vulname)])
#print(crivul)

df5=pd.DataFrame(crivul)
df5.columns=["漏洞名称","漏洞数量(CVE不同算多个)"]
criresult=df5.sort_values(['漏洞数量(CVE不同算多个)'], ascending=False)
df9=pd.DataFrame(criresult)
df9.to_excel(writer,sheet_name="Critical漏洞统计",index=False)
hivul=[]
for vulname2 in highvul:
    if [vulname2,highvul.count(vulname2)] not in hivul:
        hivul.append([vulname2,highvul.count(vulname2)])
#print(hivul)
df6=pd.DataFrame(hivul)
df6.columns=["漏洞名称","漏洞数量(CVE不同算多个)"]
hiresult=df6.sort_values(['漏洞数量(CVE不同算多个)'], ascending=False)
df10=pd.DataFrame(hiresult)
df10.to_excel(writer,sheet_name="High漏洞统计",index=False)

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
