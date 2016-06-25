from misc.Logger import logger
from wrapper.ec2 import Ec2
from wrapper.vpc import Vpc
from misc import Misc


class generate(object):
    def __init__(self):
        logger.debug("Starting generate object")

    def regions_with_azs(self):
        e = Ec2()
        regions = e.get_regions()
        for region in regions:
            name = region.get('RegionName')
            print "Region: %s" % (name,)
            r = Ec2(region=name)
            azs = r.get_all_availability_zones(filter=[{'Name': 'region-name', 'Values': [name]}])
            for a in azs:
                print "    - %s: %s" % (a.get('ZoneName'), a.get('State'))

    def envs_with_domains(self):
        v = Vpc()
        envs = v.get_active_envs()
        res = {}
        for env in envs:
            res[env] = []
            vpc = v.get_vpc_from_env(env=env)
            domain = Misc.get_value_from_array_hash(dictlist=vpc.get('Tags'), key='Domain')
            res[env].append(domain)
            logger.debug('Working on env %s and domain %s' % (env, domain))
            split_domain = Misc.string_to_array(string=domain)
            last_dn = split_domain.pop()
            # local entry
            if env == "prod":
                local_tmp = ["prod"] + split_domain + ['local']
            else:
                local_tmp = split_domain + ['local']
            res[env].append(Misc.join_list_to_string(list=local_tmp, join_with='.'))
        return res
