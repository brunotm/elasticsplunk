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


# Elasticsearch document metadata keys
ES_KEYS = ("_index", "_type", "_id", "_score")

# Time units for relative time conversion
UNITS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "M": 2592000,
    "y": 31104000,
}

# Supported actions
ACTION_SEARCH = "search"
ACTION_INDICES_LIST = "indices-list"
ACTION_CLUSTER_HEALTH = "cluster-health"


@Configuration()
class ElasticSplunk(GeneratingCommand):
    """ElasticSplunk custom search command"""

    action = Option(require=False, default=ACTION_SEARCH, doc="[search,indices-list,cluster-health")
    eaddr = Option(require=True, default=None, doc="[https]server:port,[https]server:port or config item")
    index = Option(require=False, default=None, doc="Index to search")
    #index = Option(require=False, default="_all", doc="Index to search")
    scan = Option(require=False, default=True, doc="Perform a scan search")
    stype = Option(require=False, default=None, doc="Source/doc_type")
    tsfield = Option(require=False, default=None, doc="Field holding the event timestamp")
    query = Option(require=False, default="*", doc="Query string in ES DSL")
    fields = Option(require=False, default=None, doc="Only include selected fields")
    limit = Option(require=False, default=10000, doc="Max number of hits")
    include_es = Option(require=False, default=False, doc="Include Elasticsearch relevant fields")
    include_raw = Option(require=False, default=False, doc="Include event source")
    use_ssl = Option(require=False, default=None, doc="Use SSL")
    verify_certs = Option(require=False, default=None, doc="Verify SSL Certificates")
    earliest = Option(require=False, default="now-1h",
                      doc="Earliest event, format relative eg. now-4h or 2016-11-18T23:45:00")
    latest = Option(require=False, default="now",
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
            config["hosts"] = self.eaddr.split(",")

        if self.tsfield:
            config["tsfield"] = self.tsfield
        elif "tsfield" not in config:
            config["tsfield"] = "time"
            # raise Exception("Required tsfield parameter not specified")

        # Handle SSL connections
        if self.use_ssl != None:
            config["use_ssl"] = True if self.use_ssl == "true" else False
        elif "use_ssl" not in config:
            config["use_ssl"] = False

        if not config["use_ssl"]:
            config["verify_certs"] = False
        elif self.verify_certs != None:
            config["verify_certs"] = True if self.verify_certs == "true" else False
        elif "verify_certs" not in config:
            config["verify_certs"] = False

        # Fields to fetch
        if self.fields:
            config["fields"] = self.fields.split(",")
            if not config["tsfield"] in config["fields"]:
                config["fields"].append(config["tsfield"])
        else:
            config["fields"] = None

        # source type
        config["stype"] = self.stype.split(",") if self.stype else None

        if hasattr(self.search_results_info, "endTime"):
            config["latest"] = int(self.search_results_info.endTime)
        else:
            config["latest"] = self.parse_dates(self.latest)

        if hasattr(self.search_results_info, "startTime"):
            config["earliest"] = int(self.search_results_info.startTime)
        else:
            config["earliest"] = config["latest"] - self.parse_dates(self.earliest)

        config["scan"] = self.scan
        config["index"] = self.index
        config["include_es"] = self.include_es
        config["include_raw"] = self.include_raw
        config["limit"] = self.limit
        config["query"] = self.query

        return config


    def _parse_hit(self, config, hit):
        """Parse a Elasticsearch Hit"""

        event = {}
        event["_time"] = hit["_source"][config["tsfield"]]
        for key in hit["_source"]:
            if key != config["tsfield"]:
                event[key] = hit["_source"][key]

        if config["include_es"]:
            for key in ES_KEYS:
                event["es{0}".format(key)] = hit[key]

        if config["include_raw"]:
            event["_raw"] = json.dumps(hit)

        return event


    def _list_indices(self, esclient):
        """List indices in given Elasticsearch nodes"""

        indices = esclient.indices.get('*')
        for name in indices:
            pprint(name)
            event = {}
            event["_time"] = int(time.time())
            event["name"] = name
            event["aliases"] = ",".join(indices[name]["aliases"].keys())
            event["mappings"] = ",".join(indices[name]["mappings"].keys())
            event["creation_date"] = indices[name]["settings"]["index"]["creation_date"]
            event["number_of_shards"] = indices[name]["settings"]["index"]["number_of_shards"]
            event["uuid"] = indices[name]["settings"]["index"]["uuid"]
            yield event

    def _cluster_health(self, esclient):
        """Fetch cluster status"""
        status = esclient.cluster.health()
        status["_time"] = int(time.time())
        yield status

    def _search(self, esclient, config):
        """Search Generate events to Splunk from a Elasticsearch search"""

        # Search body
        # query-string-syntax
        # www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html
        body = {
            "sort":[{config["tsfield"]:{"order": "asc"}}],
            "query": {
                "bool": {
                    "must": [
                        {"range": {
                            config["tsfield"]: {
                                "gte": config["earliest"],
                                "lte": config["latest"],
                            }
                        }},
                        {"query_string" : {
                            "query" : config["query"],
                        }}
                    ]
                }
            }
        }

        # Execute search
        if self.scan:
            res = helpers.scan(esclient,
                               size=config["limit"],
                               index=config["index"],
                               _source_include=config["fields"],
                               doc_type=config["stype"],
                               query=body)
            for hit in res:
                yield self._parse_hit(config, hit)
        else:
            res = esclient.search(index=config["index"],
                                  size=config["limit"],
                                  _source_include=config["fields"],
                                  doc_type=config["stype"],
                                  body=body)
            for hit in res['hits']['hits']:
                yield self._parse_hit(config, hit)

    def generate(self):
        """Generate events to Splunk"""

        # Get config
        config = self._get_search_config()

        # Create Elasticsearch client
        esclient = Elasticsearch(
            config["hosts"],
            verify_certs=config["verify_certs"],
            use_ssl=config["use_ssl"])

        if self.action == ACTION_SEARCH:
            return self._search(esclient, config)
        if self.action == ACTION_INDICES_LIST:
            return self._list_indices(esclient)
        if self.action == ACTION_CLUSTER_HEALTH:
            return self._cluster_health(esclient)

dispatch(ElasticSplunk, sys.argv, sys.stdin, sys.stdout, __name__)
