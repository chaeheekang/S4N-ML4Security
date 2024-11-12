# Splunk4Ninjas - Machine Learning for Security
- 워크샵 이벤트 등록: https://show.splunk.com/event/673152beb7367c17bf48b8c2 
- [교육 자료 PDF](./[2daysSC]%20Splunk4Ninjas%20-%20Machine%20Learning%20for%20Security.pdf)
## Lab 1 - Detect Remote Password Spraying attacks
### Method 1 - using SPL
```
index="main" sourcetype="XmlWinEventLog_ws" EventCode=4625 LogonType=3 
| bucket span=2m _time 
| stats dc(TargetUserName) as unique_accounts values(TargetUserName) as
  tried_accounts by _time, IpAddress, LogonType, dvc
| eventstats avg(unique_accounts) as comp_avg, stdev(unique_accounts) as comp_std
  by IpAddress, LogonType, dvc 
| eval upperBound=(comp_avg+comp_std*2)
| eval isOutlier=if(unique_accounts > 6 AND unique_accounts >= upperBound, 1, 0)
| search isOutlier=1 
```

### Method 2 - using MLTK
```
index="main" sourcetype="XmlWinEventLog_ws" EventCode=4625 LogonType=3 
| bucket span=2m _time 
| stats dc(TargetUserName) as unique_accounts values(TargetUserName) as
  tried_accounts by _time, IpAddress, LogonType, dvc
| eventstats avg(unique_accounts) as comp_avg, stdev(unique_accounts) as comp_std
  by IpAddress, LogonType, dvc 
| eval HourOfDay = strftime(_time,"%H")
| eval HourOfDay = floor(HourOfDay/4)*4
| eval DayofWeek = strftime(_time,"%w")
| eval isWeekend = if(DayOfWeek >= 1 AND DayOfWeek <= 5, 0,1)
```

## Lab 2 - Privilege Escalation
### Method 1 - using SPL
- 정말정말 간단하게 사용해 보면요...
```
index="main" source="*WinEventLog:Security" EventCode=4648
| timechart count by src_user
```
- 표준 편차를 적용해 볼까요? 
```
index="main" source="*WinEventLog:Security" EventCode=4648 
| bucket span=1d _time 
| stats count by _time, src_user 
| eventstats stdev(count) as std_dev_count, avg(count) as avg_dev_count, perc99(count) as per99 
| eval upperBound=(avg_dev_count+std_dev_count*2) 
| table upperBound, avg_dev_count, per99
| head 1
```
- 2σ 밖에 있는 값을 찾아봅시다! 
```
index="main" source="*WinEventLog:Security" EventCode=4648 
| bucket span=1d _time 
| stats count by _time, src_user 
| eventstats stdev(count) as std_dev_count, avg(count) as avg_dev_count, perc99(count) as per99, perc95(count) as per95 
| eval upperBound=(avg_dev_count+std_dev_count*2) 
| eval isOutlier=if(count >= upperBound, 1, 0) 
| search isOutlier=1
```
### Method 2 - using MLTK
```
index=main source="*WinEventLog:Security" EventCode=4648 
| bucket _time span=1d | stats count by src_user _time
```
## Lab3 - Detecting Categorical Outliers
### Detect Categorical Outliers using MLTK
```
index=* TERM(agent) sourcetype="stream:http" src_ip="*" http_user_agent="*"
| table http_user_agent, action, dest_port, bytes_in, bytes_out
```

### Clustering using SPL
```
index=* TERM(agent) sourcetype="stream:http" src_ip="*" http_user_agent="*"
| table http_user_agent, src_ip, dest_ip, action, dest_port, bytes_in, bytes_out
| head 3000
| fit TFIDF http_user_agent
| fit KMeans k=5 http_user_agent_tfidf_*
| stats values(http_user_agent) by cluster
```

### Detecting Categorical Outliers
```
index=* TERM(agent) sourcetype="stream:http" src_ip="*" http_user_agent="*"
| table http_user_agent, src_ip, dest_ip, action, dest_port, bytes_in, bytes_out
| head 3000
| fit TFIDF http_user_agent
| fit KMeans k=1 http_user_agent_tfidf_*
| fields - http_user_agent_tfidf_*
| stats max(cluster_distance) by cluster http_user_agent
| sort - max(cluster_distance)
```

## Lab 4 - Splunk App for Anomaly Detection
```
index="main" sourcetype="XmlWinEventLog_ws" EventCode=4625 LogonType=3 
| bucket span=2m _time 
| stats dc(TargetUserName) as unique_accounts values(TargetUserName) as tried_accounts by _time, IpAddress, LogonType, dvc
```