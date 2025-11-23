from typing import List
from .. import IocHit, IocReport, Pipeline
import sys, os, math, re
from . import aggregate_report, entrophy_scan, macro_scan, network_scan, obfuscation_scan
import olefile


class CfbfPipeline(Pipeline):
    ENTROPY_THRESHHOLD = 7
    RE_EMBED_EXE = re.compile(r'[\w\-\./ ]+\.(exe|dll|scr|bat|ps1|js|vbs)', re.IGNORECASE)
    RE_MZ = re.compile(br'MZ')   # binary search
    
    def __init__(self, filename):
        self.filename = filename
    
    def run(self) -> IocReport:
        if not os.path.isfile(self.filename):
            print('ERROR: file not found:', self.filename, file=sys.stderr); sys.exit(2)

        try:
            streams = self.list_streams_with_ole(self.filename)
        except Exception as e:
            print('ERROR reading OLE file with olefile:', e, file=sys.stderr)
            streams = self.list_streams_fallback(self.filename)

        stream_results = []
        for data in streams:
            res = self.analyze_stream(data, entropy_threshold=CfbfPipeline.ENTROPY_THRESHHOLD)
            stream_results += res

        report = aggregate_report(stream_results)

        return report

    
    def analyze_stream(self, data: bytes, entropy_threshold: int) -> List[IocHit]:
        hits = []

        # binary checks
        if CfbfPipeline.RE_MZ.search(data):
            hit = {}
            hit['name'] = 'embedded_MZ'
            hit['description'] = 'Document likely contains embedded MZ'
            hit['hits'] = len(CfbfPipeline.RE_MZ.findall(data))
            hit['score'] = 40
            hits.append(IocHit(**hit))

        # look for PK (zip) signatures (embedded docx/zip)
        if b'PK\x03\x04' in data:
            hit = {}
            hit['name'] = 'embedded_PK_zip'
            hit['description'] = 'Document likely contains embedded CFBF/zip'
            hit['hits'] = len(re.compile(b'PK\x03\x04').findall(data))
            hit['score'] = 20
            hits.append(IocHit(**hit))
            
        # high entropy
        ent = entrophy_scan(data)
        if ent >= entropy_threshold:
            hit = {}
            hit['name'] = 'high_entropy'
            hit['description'] = f'High entropy of {ent} detected in one of CFBF streams which can indicate raw binary data embedded into the document'
            hit['hits'] = 1
            hit['score'] = 10
            hits.append(IocHit(**hit))
                        
        # try to decode as text for regex scanning
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            text = data.decode('latin-1', errors='replace')

        hits += self.score_stream_texts(text)
                   
        return hits

    def list_streams_with_ole(self, path: str):
        ole = olefile.OleFileIO(path)
        streams = []
        for entry in ole.listdir(streams=True, storages=False):
            try:
                data = ole.openstream(entry).read()
            except Exception:
                data = b''
            streams.append(data)
        ole.close()
        return streams
    
    def list_streams_fallback(self, path: str):
        # Very limited fallback: returns a single "Raw" stream containing whole file.
        with open(path, 'rb') as f:
            data = f.read()
        return [data]

    
    def score_stream_texts(self, text: str) -> List[IocHit]:
        hits = []
        hits += macro_scan(text)
        hits += network_scan(text)
        hits += obfuscation_scan(text)
        
        if CfbfPipeline.RE_EMBED_EXE.search(text):
            fnames = list(set(CfbfPipeline.RE_EMBED_EXE.findall(text)))

            hits.append(IocHit(
                name='embedded_filename',
                description=f'Embedded filenames are detected: {fnames}',
                score=40,
                hits=len(CfbfPipeline.RE_EMBED_EXE.findall(text))
            ))
            
        return hits