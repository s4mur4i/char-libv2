import boto3
from misc.Logger import logger
from misc import Misc


class Kinesis(object):
    def __init__(self, region='us-east-1'):
        logger.debug("Starting Kinesis for kinesis")
        self.kinesis = boto3.client('kinesis', region_name=region)

    def describe_kinesis_stream(self, stream_name=None, limit=None, exclusive_start_shard_id=None):
        resp = self.kinesis.describe_stream(StreamName=stream_name)
        return resp

    def get_kinesis_stream_shard_iterator_by_shard_id(self, stream_name=None, shard_id=None, shard_iterator_type=None):
        resp = self.kinesis.get_shard_iterator(StreamName=stream_name, ShardId=shard_id,
                                               ShardIteratorType=shard_iterator_type)
        iterator = resp['ShardIterator']
        return iterator

    def get_kinesis_stream_records_by_iterator(self, shard_iterator=None):
        resp = self.kinesis.get_records(ShardIterator=shard_iterator)
        return resp

    def get_kinesis_shard_ids(self, stream=None):
        shard_ids = []
        for shard in stream['StreamDescription']['Shards']:
            shard_ids.append(shard['ShardId'])
        return shard_ids
