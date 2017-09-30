# ElasticSplunk
# Search ElasticSearch within Splunk
#
# Written by Bruno Moura <brunotm@gmail.com>
#

import os
import re
import sys
import json
import time
from pprint import pprint
from elasticsearch import Elasticsearch, helpers
from splunklib.searchcommands import \
    dispatch, GeneratingCommand, Configuration, Option, validators


# Time units for relative time conversion
UNITS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "M": 2592000,
    "y": 31104000,
}

# Elasticsearch document metadata keys
KEYS_ELASTIC = ("_index", "_type", "_id", "_score")
KEY_ELASTIC_SOURCE = "_source"

# Supported actions
ACTION_SEARCH = "search"
ACTION_INDICES_LIST = "indices-list"
ACTION_CLUSTER_HEALTH = "cluster-health"

# Config keys
KEY_CONFIG_EADDR = "hosts"
KEY_CONFIG_TIMESTAMP = "tsfield"
KEY_CONFIG_USE_SSL = "use_ssl"
KEY_CONFIG_VERIFY_CERTS = "verify_certs"
KEY_CONFIG_FIELDS = "fields"
KEY_CONFIG_SOURCE_TYPE = "stype"
KEY_CONFIG_LATEST = "latest"
KEY_CONFIG_EARLIEST = "earliest"
KEY_CONFIG_SCAN = "scan"
KEY_CONFIG_INDEX = "index"
KEY_CONFIG_INCLUDE_ES = "include_es"
KEY_CONFIG_INCLUDE_RAW = "include_raw"
KEY_CONFIG_LIMIT = "limit"
KEY_CONFIG_QUERY = "query"

# Splunk keys
KEY_SPLUNK_TIMESTAMP = "_time"
KEY_SPLUNK_EARLIEST = "startTime"
KEY_SPLUNK_LATEST = "endTime"
KEY_SPLUNK_RAW = "_raw"

# Default time range
DEFAULT_EARLIEST = "now-24h"
DEFAULT_LATEST = "now"

@Configuration()
class ElasticSplunk(GeneratingCommand):
    """ElasticSplunk custom search command"""

    action = Option(require=False, default=ACTION_SEARCH, doc="[search,indices-list,cluster-health")
    eaddr = Option(require=True, default=None, doc="server:port,server:port or config item")
    index = Option(require=False, default=None, doc="Index to search")
    #index = Option(require=False, default="_all", doc="Index to search")
    scan = Option(require=False, default=True, doc="Perform a scan search")
    stype = Option(require=False, default=None, doc="Source/doc_type")
    tsfield = Option(require=False, default="@timestamp", doc="Field holding the event timestamp")
    query = Option(require=False, default="*", doc="Query string in ES DSL")
    fields = Option(require=False, default=None, doc="Only include selected fields")
    limit = Option(require=False, default=10000, doc="Max number of hits")
    include_es = Option(require=False, default=False, doc="Include Elasticsearch relevant fields")
    include_raw = Option(require=False, default=False, doc="Include event source")
    use_ssl = Option(require=False, default=None, doc="Use SSL")
    verify_certs = Option(require=False, default=None, doc="Verify SSL Certificates")
    earliest = Option(require=False, default=None,
                      doc="Earliest event, format relative eg. now-4h or 2016-11-18T23:45:00")
    latest = Option(require=False, default=None,
                    doc="Latest event, format 2016-11-17T23:45:00")

    @staticmethod
    def parse_dates(time_value):
        """Parse relative dates if specified"""

        if isinstance(time_value, int):
            return time_value

        if re.search(r"^now$", time_value):
            return int(time.time())

        match = re.search(r"^now-(\d+)([a-zA-Z])$", time_value)
        if match:
            multi, unit = match.groups()
            return int(multi) * UNITS[unit]

        if re.search(r"^\d{4}-\d{2}-\d{2}$", time_value):
            return int(time.mktime(time.strptime(time_value, "%Y-%m-%d")))

        if re.search(r"^\d{4}-\d{2}-\d{2}T\d{2}$", time_value):
            return int(time.mktime(time.strptime(time_value, "%Y-%m-%dT%H")))

        if re.search(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$", time_value):
            return int(time.mktime(time.strptime(time_value, "%Y-%m-%dT%H:%M")))

        if re.search(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$", time_value):
            return int(time.mktime(time.strptime(time_value, "%Y-%m-%dT%H:%M:%S")))


    def _get_search_config(self):
        """Parse and configure search parameters"""

        # Load default configs if available
        app_path = os.path.dirname(os.path.abspath(__file__)) + "/.."
        local_config = "{0}/local/elasticsplunk.json".format(app_path)
        if os.path.isfile(local_config):
            config_file = open(local_config)
            config = json.load(config_file)
        else:
            config = {}

        # Load eaddr stored config
        if self.eaddr in config:
            config = config[self.eaddr]
        else:
            config[KEY_CONFIG_EADDR] = self.eaddr.split(",")

        if KEY_CONFIG_TIMESTAMP not in config:
            config[KEY_CONFIG_TIMESTAMP] = self.tsfield
            # raise Exception("Required tsfield parameter not specified")

        # Handle SSL connections
        if self.use_ssl != None:
            config[KEY_CONFIG_USE_SSL] = True if self.use_ssl == "true" else False
        elif KEY_CONFIG_USE_SSL not in config:
            config[KEY_CONFIG_USE_SSL] = False

        if not config[KEY_CONFIG_USE_SSL]:
            config[KEY_CONFIG_VERIFY_CERTS] = False
        elif self.verify_certs != None:
            config[KEY_CONFIG_VERIFY_CERTS] = True if self.verify_certs == "true" else False
        elif KEY_CONFIG_VERIFY_CERTS not in config:
            config[KEY_CONFIG_VERIFY_CERTS] = False

        # Fields to fetch
        if self.fields:
            config[KEY_CONFIG_FIELDS] = self.fields.split(",")
            if not config[KEY_CONFIG_TIMESTAMP] in config[KEY_CONFIG_FIELDS]:
                config[KEY_CONFIG_FIELDS].append(config[KEY_CONFIG_TIMESTAMP])
        else:
            config[KEY_CONFIG_FIELDS] = None

        # source type
        config[KEY_CONFIG_SOURCE_TYPE] = self.stype.split(",") if self.stype else None

        if self.latest:
            config[KEY_CONFIG_LATEST] = self.parse_dates(self.latest)
        elif hasattr(self.search_results_info, KEY_SPLUNK_LATEST):
            config[KEY_CONFIG_LATEST] = int(self.search_results_info.endTime)
        else:
            config[KEY_CONFIG_LATEST] = self.parse_dates(DEFAULT_LATEST)

        if self.earliest:
            config[KEY_CONFIG_EARLIEST] = config[KEY_CONFIG_LATEST] - self.parse_dates(self.earliest)
        elif hasattr(self.search_results_info, KEY_SPLUNK_EARLIEST):
             config[KEY_CONFIG_EARLIEST] = int(self.search_results_info.startTime)
        else:
            config[KEY_CONFIG_EARLIEST] = config[KEY_CONFIG_LATEST] - self.parse_dates(DEFAULT_EARLIEST)

        config[KEY_CONFIG_SCAN] = self.scan
        config[KEY_CONFIG_INDEX] = self.index
        config[KEY_CONFIG_INCLUDE_ES] = self.include_es
        config[KEY_CONFIG_INCLUDE_RAW] = self.include_raw
        config[KEY_CONFIG_LIMIT] = self.limit
        config[KEY_CONFIG_QUERY] = self.query

        return config


    def _parse_hit(self, config, hit):
        """Parse a Elasticsearch Hit"""

        event = {}
        event[KEY_SPLUNK_TIMESTAMP] = hit[KEY_ELASTIC_SOURCE][config[KEY_CONFIG_TIMESTAMP]]
        for key in hit[KEY_ELASTIC_SOURCE]:
            if key != config[KEY_CONFIG_TIMESTAMP]:
                event[key] = hit[KEY_ELASTIC_SOURCE][key]

        if config[KEY_CONFIG_INCLUDE_ES]:
            for key in KEYS_ELASTIC:
                event["es{0}".format(key)] = hit[key]

        if config[KEY_CONFIG_INCLUDE_RAW]:
            event[KEY_SPLUNK_RAW] = json.dumps(hit)

        return event


    def _list_indices(self, esclient):
        """List indices in given Elasticsearch nodes"""

        indices = esclient.indices.get('*')
        for name in indices:
            pprint(name)
            event = {}
            event[KEY_SPLUNK_TIMESTAMP] = int(time.time())
            event["name"] = name
            event["aliases"] = ",".join(indices[name]["aliases"].keys())
            event["mappings"] = ",".join(indices[name]["mappings"].keys())
            event["creation_date"] = indices[name]["settings"]["index"]["creation_date"]
            event["number_of_shards"] = indices[name]["settings"]["index"]["number_of_shards"]
            event["number_of_replicas"] = indices[name]["settings"]["index"]["number_of_replicas"]
            event["uuid"] = indices[name]["settings"]["index"]["uuid"]
            yield event

    def _cluster_health(self, esclient):
        """Fetch cluster status"""
        status = esclient.cluster.health()
        status[KEY_SPLUNK_TIMESTAMP] = int(time.time())
        yield status

    def _search(self, esclient, config):
        """Search Generate events to Splunk from a Elasticsearch search"""

        # Search body
        # query-string-syntax
        # www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html
        body = {
            "sort":[{config[KEY_CONFIG_TIMESTAMP]:{"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {
                            config[KEY_CONFIG_TIMESTAMP]: {
                                "gte": config[KEY_CONFIG_EARLIEST],
                                "lte": config[KEY_CONFIG_LATEST],
                                "format": "epoch_second",
                            }
                        }},
                        {"query_string" : {
                            "query" : config[KEY_CONFIG_QUERY],
                        }}
                    ]
                }
            }
        }

        # Execute search
        if self.scan:
            res = helpers.scan(esclient,
                               size=config[KEY_CONFIG_LIMIT],
                               index=config[KEY_CONFIG_INDEX],
                               _source_include=config[KEY_CONFIG_FIELDS],
                               doc_type=config[KEY_CONFIG_SOURCE_TYPE],
                               query=body)
            for hit in res:
                yield self._parse_hit(config, hit)
        else:
            res = esclient.search(index=config[KEY_CONFIG_INDEX],
                                  size=config[KEY_CONFIG_LIMIT],
                                  _source_include=config[KEY_CONFIG_FIELDS],
                                  doc_type=config[KEY_CONFIG_SOURCE_TYPE],
                                  body=body)
            for hit in res['hits']['hits']:
                yield self._parse_hit(config, hit)

    def generate(self):
        """Generate events to Splunk"""

        # Get config
        config = self._get_search_config()

        # Create Elasticsearch client
        esclient = Elasticsearch(
            config[KEY_CONFIG_EADDR],
            verify_certs=config[KEY_CONFIG_VERIFY_CERTS],
            use_ssl=config[KEY_CONFIG_USE_SSL])

        if self.action == ACTION_SEARCH:
            return self._search(esclient, config)
        if self.action == ACTION_INDICES_LIST:
            return self._list_indices(esclient)
        if self.action == ACTION_CLUSTER_HEALTH:
            return self._cluster_health(esclient)

dispatch(ElasticSplunk, sys.argv, sys.stdin, sys.stdout, __name__)
