import logging
import sys
import csv
import collections
from prettytable import PrettyTable as PrettyTable,ALL

class Logger(object):
    def __init__(self,name="kerrigan"):
        """
        This function is the initial object constructor
        :param name: The unix application name that shold be used
        :return: None
        """
        self.ilog = logging.getLogger(name)
        self.ilog.setLevel(logging.DEBUG)
        # Console printing
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.ilog.addHandler(ch)
        self.verbosity = 3
        self.verbosity_parser()

    def change_name(self,name):
        verbosity = self.verbosity
        self.__init__(name=name)
        self.verbosity = verbosity

    def verbosity_parser(self):
        """
        This function is used to parse the verbosity level that is needed. CLI arguments
        parsed are removed from CLI dict
        :return: None
        """
        for arg in sys.argv[1:]:
            if arg == '-v':
                self.verbosity += 1
                sys.argv.remove('-v')
            elif arg == '--verbose':
                self.verbosity += 1
                sys.argv.remove('--verbose')
            elif arg == '--quiet':
                self.verbosity -= 1
                sys.argv.remove('--quiet')
            elif arg == '-q':
                self.verbosity -= 1
                sys.argv.remove('-q')

            if self.verbosity > 5:
                self.verbosity = 5
            elif self.verbosity < 0:
                self.verbosity = 0


    def critical(self, msg):
        """
        This function is used to print critical messages
        Execution should be halted, engineer intervention is needed
        :param msg: The message to print
        :return: None
        """
        # verbosity = 1
        if self.verbosity >= 1:
            self.ilog.critical(msg)


    def error(self, msg):
        """
        This function is used to print error messages
        Execution might be halted depending on error
        :param msg: The message to print
        :return: None
        """
        # verbosity = 2
        if self.verbosity >= 2:
            self.ilog.error(msg)


    def warning(self, msg):
        """
        This function is used to print warning messages
        Execution is not halted at this point
        :param msg: The message to print
        :return: None
        """
        # verbosity = 3
        if self.verbosity >= 3:
            self.ilog.warning(msg)


    def info(self, msg):
        """
        This function is used to print informational messages
        :param msg: The message to print
        :return: None
        """
        # verbosity = 4
        if self.verbosity >= 4:
            self.ilog.info(msg)


    def debug(self, msg):
        """
        This function prints on highest level
        Used for printing the state machine
        :param msg: The message to print
        :return: None
        """
        # verbosity = 5
        if self.verbosity >= 5:
            self.ilog.debug(msg)


    def echo(self, msg):
        """
        This function just prints a message.
        Should only be used during development
        :param msg: The mssage to print
        :return: None
        """
        # verbosity = 3
        if self.verbosity >= 3:
            print("%s" % (msg,))


    def output(self, csvvar=None, tablevar=None,data=None):
        """
        This function prints in csv or table format
        :param csvvar: Boolean if csv format should be used
        :type csvvar: bool
        :param tablevar: Boolean if table format should be used
        :type tablevar: bool
        :param data: A dict with hashes to print
        :return: None
        """
        field_names = None
        try:
            if data and data[0]:
                od = collections.OrderedDict(sorted(data[0].items()))
                field_names = list(od.keys())
        except:
            exit(1)
        if tablevar and field_names:
            table = PrettyTable()
            table.hrules = ALL
            table.field_names = field_names
            table.max_width = 80
            for item in data:
                ordered_item = collections.OrderedDict(sorted(item.items()))
                table.add_row(list(ordered_item.values()))
            print(table)
        if csvvar:
            writer = csv.DictWriter(sys.stdout, delimiter=';', fieldnames=field_names)
            writer.writeheader()
            for item in data:
                ordered_item = collections.OrderedDict(sorted(item.items()))
                writer.writerow(ordered_item)


logger = Logger()