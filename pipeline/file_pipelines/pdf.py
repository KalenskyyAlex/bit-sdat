from .. import IocReport, Pipeline

class PdfPipeline(Pipeline):
    def __init__(self, filename):
        self.filename = filename
    
    def run(self) -> IocReport:
        raise SyntaxError('TODO Not Implemented')
