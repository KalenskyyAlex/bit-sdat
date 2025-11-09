from . import Pipeline

class GeneratePdfPipeline(Pipeline):
    def __init__(self, output, filename = None, content = None):
        if not filename and not content:
            raise ValueError('Provide either filename or content')
        
        self.filename = filename,
        self.output = output
        self.content = content
        
    def run(self):
        raise SyntaxError('TODO Not Implemented')

