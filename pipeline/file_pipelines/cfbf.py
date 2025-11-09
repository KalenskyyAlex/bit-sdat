from .. import IocReport, Pipeline

class CfbfPipeline(Pipeline):
    def __init__(self, filename):
        self.filename = filename
    
    def run(self) -> IocReport:
        raise SyntaxError('TODO Not Implemented')
