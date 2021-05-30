# NessusReport
将Nessus按默认字段导出的CSV报表转为中文xlsx（包含sheet:扫描信息、扫描资产、漏洞统计、Critical漏洞统计、High漏洞统计、漏洞详情）

## 扫描信息
![](https://github.com/jeansgit/NessusReport/blob/main/%E6%89%AB%E6%8F%8F%E4%BF%A1%E6%81%AF.bmp)
## 扫描资产
![](https://github.com/jeansgit/NessusReport/blob/main/%E6%89%AB%E6%8F%8F%E8%B5%84%E4%BA%A7.bmp)
## 漏洞统计（风险等级）
![](https://github.com/jeansgit/NessusReport/blob/main/%E6%BC%8F%E6%B4%9E%E7%BB%9F%E8%AE%A1.bmp)
## Critical漏洞统计
![](https://github.com/jeansgit/NessusReport/blob/main/Critical%E6%BC%8F%E6%B4%9E%E7%BB%9F%E8%AE%A1.bmp)
## High漏洞统计
![](https://github.com/jeansgit/NessusReport/blob/main/high%E6%BC%8F%E6%B4%9E%E7%BB%9F%E8%AE%A1.bmp)
## 漏洞详情
![](https://github.com/jeansgit/NessusReport/blob/main/%E6%BC%8F%E6%B4%9E%E8%AF%A6%E6%83%85.bmp)


# 用法
## 转换前
![](https://github.com/jeansgit/NessusReport/blob/main/%E8%BD%AC%E6%8D%A2%E5%89%8D.bmp)

## 命令
将nessusvul.7z解压后的nessusvul.db文件放在与NessusCsvReport.py同一目录

python NessusCsvReport.py nessustest.csv result.xlsx
![](https://github.com/jeansgit/NessusReport/blob/main/%E8%BD%AC%E4%B8%BA%E4%B8%AD%E6%96%87.bmp)
