import boto3

from misc.Logger import logger


class Sqs(object):
    def __init__(self):
        logger.debug("Starting EC2Class for sqs")
        self.boto3 = boto3.client('sqs')

    def get_url(self, url=None):
        logger.debug("Searching url for %s" % (url,))
        resp = self.boto3.get_queue_url(QueueName=url)
        logger.debug("Response is %s" % (resp['QueueUrl']))
        return resp['QueueUrl']

    def send_msg(self, msg=None, url=None, attribs=None):
        logger.debug("Sending msg %s to %s" % (msg, url))
        if attribs:
            resp = self.boto3.send_message(QueueUrl=url, MessageBody=msg, attribs=attribs)
        else:
            resp = self.boto3.send_message(QueueUrl=url, MessageBody=msg)
        logger.debug("Message details: Md5: %s, MsgID: %s" % (resp['MD5OfMessageBody'], resp['MessageId']))

    def recieve_msg(self, url=None, filter=None):
        logger.debug("Recieving messages for url : %s" % (url,))
        if filter:
            resp = self.boto3.recieve_message(QueueUrl=url, MessageAttributeNames=filter)
        else:
            resp = self.boto3.recieve_message(QueueUrl=url)
        return resp['Messages']

    def delete_msg(self, url=None, receipthandle=None):
        resp = self.boto3.delete_message(QueueUrl=url, ReceiptHandle=receipthandle)
        print resp

    def list_queues(self):
        resp = self.boto3.list_queues()
        return resp['QueueUrls']
