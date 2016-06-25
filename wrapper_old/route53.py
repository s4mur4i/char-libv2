import boto3

from misc.Logger import logger
from misc import Misc


class Route53(object):
    def __init__(self):
        logger.debug("Starting EC2Class for route53")
        self.boto3 = boto3.client('route53', region_name='us-east-1')

    def list_hosted_zones(self):
        zones = self.boto3.list_hosted_zones_by_name()
        if zones['IsTruncated']:
            logger.error("Response is truncated, need to implement paging")
        return zones['HostedZones']

    def list_zone_records(self, zoneid=None):
        records = self.boto3.list_resource_record_sets(HostedZoneId=zoneid)
        if records['IsTruncated']:
            logger.error("Response is truncated, need to implement paging")
        return records['ResourceRecordSets']

    def get_zoneid_from_domain(self, domain=None):
        zones = self.list_hosted_zones()
        logger.debug("Searching for domain %s" % (domain,))
        concat = domain + '.'
        logger.debug("Concated domain name is %s" % (concat,))
        for zone in zones:
            if zone['Name'] == concat:
                if zone['Id'].startswith('/hostedzone/'):
                    tmp = zone['Id'].replace('/hostedzone/', '')
                    return tmp
                else:
                    return zone['Id']
        logger.error("Could not find zone with domain name")
        return None

    def manage_gw_for_route53(self, ips=None, zoneid=None, domain=None, dryrun=None):
        logger.debug("Checking if need to add IPs to route53")
        records = self.list_zone_records(zoneid=zoneid)
        for ip in ips['active']:
            logger.debug("Checking ip %s" % (ip,))
            if record_exists(records=records, name="broker.%s." % (domain,), ip=ip):
                logger.info("Found IP Entry %s in route53 domain %s" % (ip, domain))
                continue
            else:
                logger.info("Did not find the IP in the route53, adding them")
                self.add_gw_to_route53(ips=ips['active'], zoneid=zoneid, domain=domain, dryrun=dryrun)
                logger.debug("Ips have been updated, no point on checking further")
                break
        logger.debug("Checking if need to remove IPs from route53")
        records = self.list_zone_records(zoneid=zoneid)
        for ip in ips['deactive']:
            logger.debug("Checking if deactivate IP %s is active" % (ip,))
            if record_exists(records=records, name="broker.%s." % (domain,), ip=ip):
                logger.info("Need to remove entry %s from route53" % (ip,))
                self.add_gw_to_route53(ips=ips['active'], zoneid=zoneid, domain=domain, dryrun=dryrun)
                logger.debug("Ips have been updated, no point on checking further")
                break
        if dryrun:
            logger.debug("Dryrun configured, no need to test")
            return True
        logger.info("Refreshing records to see if change in place")
        records = self.list_zone_records(zoneid=zoneid)
        for record in records:
            if record['Name'] == "broker.%s." % (domain,):
                if len(record['ResourceRecords']) == len(ips['active']):
                    logger.info("Length of current records equals actice records")
                else:
                    logger.error("Length does not equal, something went wrong")
                break

    def add_gw_to_route53(self, ips=None, zoneid=None, domain=None, dryrun=None):
        rr = []
        for ip in ips:
            rr.append({'Value': ip})
        changes = {'Action': 'UPSERT', 'ResourceRecordSet': {
            'Name': "broker.%s." % (domain,),
            'Type': "A",
            'SetIdentifier': "broker",
            'Weight': 0,
            'TTL': 300,
            'ResourceRecords': rr,
        }}
        changebatch = {'Comment': "Update for adding %s ip to broker" % (ip,), 'Changes': [changes]}
        self.change_record_for_zoneid(zoneid=zoneid, changebatch=changebatch, dryrun=dryrun)

    def change_record_for_zoneid(self, zoneid=None, changebatch=None, dryrun=None):
        if dryrun:
            logger.debug("Dryrun requested")
            logger.warning("Not running changebatch: %s" % changebatch, )
            return True
        ret = self.boto3.change_resource_record_sets(HostedZoneId=zoneid, ChangeBatch=changebatch)
        if ret['ResponseMetadata']['HTTPStatusCode'] == 200:
            logger.info("Change was succesful")
        else:
            logger.error("There was an issue with the change")

    def manage_single_gw_record(self, domain=None, zoneid=None, machines=None, env=None, dryrun=None):
        for machine in machines.keys():
            rr = [{'Value': machines[machine]}]
            changes = {'Action': 'UPSERT', 'ResourceRecordSet': {
                'Name': "%s.%s." % (machine, domain),
                'Type': "A",
                # 'SetIdentifier': "broker_%s_%s" % (env,machine),
                # 'Weight': 0,
                'TTL': 300,
                'ResourceRecords': rr,
            }}
            changebatch = {'Comment': "Update for adding %s ip to broker unique" % (machine,), 'Changes': [changes]}
            self.change_record_for_zoneid(zoneid=zoneid, changebatch=changebatch, dryrun=dryrun)


# FIXME add customer automatisation for ELB-s

def record_exists(records=None, name=None, ip=None):
    for record in records:
        if record['Name'] == name:
            for r in record['ResourceRecords']:
                if r['Value'] == ip:
                    logger.info("Found IP Entry %s in route53" % (ip,))
                    return True
    return False
