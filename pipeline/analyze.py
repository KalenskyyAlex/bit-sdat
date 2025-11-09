from pathlib import Path
import zipfile
from . import Pipeline
from file_pipelines.cfbf import CfbfPipeline
from file_pipelines.pdf import PdfPipeline
from file_pipelines.ooxml import OoxmlPipeline
from pdf import GeneratePdfPipeline

class AnalyzePipeline(Pipeline):
    def __init__(self, filename, output, pdf):
        self.filename = filename,
        self.output = output
        self.pdf = pdf
    
    def run(self):
        calculated_type = self.detect_file_type(self.filename)
        
        report = None
        match calculated_type:
            case "PDF":
                report = PdfPipeline(self.filename).run()
            case "CFBF":
                report = CfbfPipeline(self.filename).run()
            case "OOXML":
                report = OoxmlPipeline(self.filename).run()
            case _:
                raise NotImplementedError('SDAT does not support this file type, aborting...')
        
        if self.pdf:
            GeneratePdfPipeline(self.output, content=report).run()
        else:
            with open(self.output, 'w') as f:
                f.write(report)
            
        return report    
    
    def detect_file_type(self, path: str) -> str:
        path = Path(path)
        with open(path, "rb") as f:
            header = f.read(8)

        # Check PDF
        if header.startswith(b"%PDF-"):
            return "PDF"
        # Check CFBF (OLE2)
        elif header.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
            return "CFBF"
        # Check ZIP / OOXML
        elif header.startswith(b"PK\x03\x04"):
            # further check internal files to ensure it's OOXML
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as zf:
                    names = zf.namelist()
                    if any(n.startswith("word/") for n in names):
                        return "OOXML"
                    elif any(n.startswith("xl/") for n in names):
                        return "OOXML"
                    elif any(n.startswith("ppt/") for n in names):
                        return "OOXML"
                    else:
                        return "ZIP"
            return "ZIP"
        else:
            return "Unknown"