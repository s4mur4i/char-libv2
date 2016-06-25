from misc.Logger import logger
from wrapper.rds import Rds
import csv


class awsrds(object):
    def __init__(self):
        logger.debug("Starting awsrds object")

    def get_parameter_group(self, name=None):
        r = Rds()
        ret = r.get_db_parameter_group(name=name)
        # header
        # return ret
        # FIXME return instead of write
        with open("/tmp/db_param_group_%s.csv" % (name,), 'wb') as f:
            field_names = ['ParameterName', 'ParameterValue', 'Description', 'Source', 'ApplyType', 'DataType',
                           'AllowedValues', 'IsModifiable', 'MinimumEngineVersion', 'ApplyMethod']
            writer = csv.DictWriter(f, fieldnames=field_names, delimiter=';')
            writer.writeheader()
            for value in ret:
                writer.writerow(value)
