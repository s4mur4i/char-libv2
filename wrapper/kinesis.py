from misc.Logger import logger
from wrapper.wrapper_base import wrapper_base


class Kinesis(wrapper_base):
    def __init__(self, session):
        """
        This function creates the initial client and resource objects
        :param session: a boto3 session object for connecting to aws
        :return: a wrapper.Kinesis object for running wrapper commands
        """
        logger.debug("Starting Kinesis wrapper")
        self.kinesis_client = session.client(service_name="kinesis")

    def information_kinesis_streams(self):
        """
        This function is an interface to query all
        :return: A list of stream objects
        """
        kinesis_streams = self.get_all_kinesis_streams()
        return kinesis_streams

    def get_all_kinesis_streams(self, streamname=None, with_tag=True):
        """
        This function queries requested streams, if no name is given all are returned
        :param streamname: The requested stream
        :param with_tag: Should the tags be queried seperatly
        :return: a list of streams objects requested
        """
        if streamname:
            resp = self.kinesis_client.list_streams(ExclusiveStartStreamName=streamname)
        else:
            resp = self.kinesis_client.list_streams()
        super(Kinesis, self).query_information(query=resp)
        result = []
        for stream in resp['StreamNames']:
            logger.debug("Gathering info on %s" % (stream,))
            stream_info = self.describe_stream(streamname=stream)
            if with_tag:
                tags = self.get_stream_tags(streamname=stream)
                stream_info['Tags'] = tags
            result.append(stream_info)
            logger.debug("Kinesis information: %s" % (stream_info,))
        return result

    def get_stream_tags(self, streamname):
        """
        This function queries a streams tags
        :param streamname: The requested streams name
        :return: the requested streams tags
        """
        while True:
            try:
                resp = self.kinesis_client.list_tags_for_stream(StreamName=streamname)
            except Exception as e:
                logger.warning("Kinesis list_tags_for_stream through an error, retrying")
                continue
            break
        super(Kinesis, self).query_information(query=resp)
        tags = resp['Tags']
        return tags

    def describe_stream(self, streamname):
        """
        The function returns a single stream
        :param streamname: the name of the requested stream
        :return: a dict of attributes
        """
        resp = self.kinesis_client.describe_stream(StreamName=streamname)
        super(Kinesis, self).query_information(query=resp)
        return resp['StreamDescription']

    def create_kinesis_stream(self, stream_name, shard_count):
        """
        This function creates a kinesis stream
        :param stream_name: The name of the requested stream
        :param shard_count: the requested shard count for the stream
        :return: The created stream object
        """
        stream = self.kinesis_client.create_stream(StreamName=stream_name,
                                       ShardCount=shard_count)
        super(Kinesis, self).query_information(query=stream)
        waiter = self.kinesis_client.get_waiter('stream_exists')
        waiter.wait(StreamName=stream_name)
        return stream

    def kinesis_exists(self, name):
        """
        This function tests if kinesis stream exists or not
        :param name: the name of the stream to test
        :return: boolean if stream exists
        """
        try:
            self.describe_stream(streamname=name)
            return True
        except Exception as e:
            if e.response['Error']['Code'] == "ResourceNotFoundException":
                return False
            else:
                logger.error(e)
                exit(1)

    def delete_kinesis(self, name):
        """
        This function deletes a kinesis stream
        :param name: The name of the stream to delete
        :return: None
        """
        resp = self.kinesis_client.delete_stream(StreamName=name)
        super(Kinesis, self).query_information(query=resp)
        return resp
