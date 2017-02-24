ElasticSplunk Search Command
====================================================

A Search command to explore Elasticsearch data within Splunk.

# Currently supported
- Multiple node search
- Index Specification
- SSL connections
- Scroll searches
- Fields to include
- Splunk timepicker values
- Relative time values
- Timestamp field specification
- Index listing "action=indices-list"
- Cluster health "action=cluster-health"

# Included libraries
- elasticsearch-py
- urllib3
- splunklib from the splunk-sdk-python

# Examples

## Search:
```
|ess eaddr="https://node1:9200,https://node2:9200" index=indexname tsfield="@timestamp" latest=now earliest="now-24h" query="field:value AND host:host*" 
```

## List indices
```
|ess eaddr="https://node1:9200,https://node2:9200" action=indices-list" 
```

## Cluster health
```
|ess eaddr="https://node1:9200,https://node2:9200" action=cluster-health" 
```

Written by Bruno Moura <brunotm@gmail.com>

