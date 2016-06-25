import time

from misc.Logger import logger
from lxml import etree


class XML(object):
    def __init__(self, name=None, feature=None):
        self.name = name
        self.create()
        self.start_time()
        self.feature = feature

    def create(self):
        version = "1.4.0"
        self.root = etree.Element("test-suite", version=version)
        self.root.set("xmlns", "urn:model.allure.qatools.yandex.ru")
        self.root.set("start", "")
        self.root.set("stop", "")
        title = etree.SubElement(self.root, "title")
        title.set("xmlns", "")
        title.text = self.name
        self.testcases = etree.SubElement(self.root, "test-cases")
        self.testcases.set("xmlns", "")

    def output(self):
        self.stop_time()
        file = open("%s-testsuite.xml" % (self.name,), 'w')
        # print (etree.tostring(self.root, xml_declaration=True, pretty_print=True))
        file.write(etree.tostring(self.root, xml_declaration=True, pretty_print=True))
        file.close()

    def add_feature_label(self, value=None):
        labels = etree.SubElement(self.tc, "labels")
        feature = etree.SubElement(labels, "label")
        feature.set("name", "feature")
        feature.set("value", value)

    def start_time(self):
        self.root.set("start", self.cur_time())

    def stop_time(self):
        self.root.set("stop", self.cur_time())

    def cur_time(self):
        return str(int(time.time()))

    def add_tc(self, tcname=""):
        tc = etree.SubElement(self.testcases, "test-case")
        tc.set("start", self.cur_time())
        tc.set("stop", "")
        tc.set("status", "")
        title = etree.SubElement(tc, "title")
        title.text = tcname
        steps = etree.SubElement(tc, "steps")
        self.steps = steps
        self.tc = tc
        self.add_feature_label(value=self.feature)

    def add_step(self, name=None):
        step = etree.SubElement(self.steps, "step")
        step.set("start", self.cur_time())
        step.set("stop", "")
        step.set("status", "")
        title = etree.SubElement(step, "title")
        title.text = name
        self.step = step

    def finish_step(self, status="failed", msg=None, stacktrace=None):
        self.check_status(status=status)
        self.step.set("status", status)
        self.step.set("stop", self.cur_time())
        if msg or stacktrace:
            self.failure = etree.SubElement(self.tc, "failure")
        if msg:
            message = etree.SubElement(self.failure, "message")
            message.text = msg
        if stacktrace:
            st = etree.SubElement(self.failure, "stack-trace")
            st.text = stacktrace
        if hasattr(self, 'failure'):
            logger.debug("Freeing failure object")
            self.failure = None
        self.step = None

    def finish_tc(self):
        self.tc.set("stop", self.cur_time())
        self.tc.set("status", "passed")
        for step in self.steps:
            if step.get("status") == 'failed':
                self.tc.set("status", "failed")
        self.tc = None
        self.steps = None

    def check_status(self, status=None):
        if status == "failed" or status == "passed":
            logger.debug("Valid staus option")
        else:
            logger.error("Invalid staus option %s" % (status,))
            exit(1234)
