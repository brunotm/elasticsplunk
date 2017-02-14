ElasticSplunk Search Command
====================================================

A Search command to explore Elasticsearch data within Splunk.

# Currently supported
- Multiple cluster node search
- Index Specification
- SSL connections
- Scroll searches
- Fields to include
- Splunk timepicker values
- Relative time values
- Time stamp field specification

# Included
- elasticsearch-py
- splunklib from the splunk-sdk-python

# Example
```
|ess eaddr="https://node1:9200,https://node2:9200" index=indexname tsfield="@timestamp" latest=now earliest="now-24h" query="field:value AND host:host*" 
```

Written by Bruno Moura <brunotm@gmail.com>

