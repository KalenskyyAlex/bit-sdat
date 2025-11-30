import json
from . import IocReport, Pipeline

class GeneratePdfPipeline(Pipeline):
    def __init__(self, output, filename = None, content = None):
        if not filename and not content:
            raise ValueError('Provide either filename or content')
        
        if filename and content:
            raise ValueError('Provide either filename or content')
        
        self.filename = filename,
        self.output = output
        self.content = content
        
    def run(self) -> IocReport:
        if self.filename:
            with open(self.filename, 'r') as f:
                self.content = IocReport.from_dict(json.load(f))
        
        raise SyntaxError('TODO Not Implemented')

