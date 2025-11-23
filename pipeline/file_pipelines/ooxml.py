import math
import os
import re
import sys
from typing import List
from .. import IocHit, IocReport, Pipeline
import zipfile
from . import aggregate_report, entrophy_scan, macro_scan, network_scan, obfuscation_scan

class OoxmlPipeline(Pipeline):
    ENTROPY_THRESHHOLD = 7
    RE_EMBED_EXE = re.compile(r'[\w\-\./ ]+\.(exe|dll|scr|bat|ps1|js|vbs)', re.IGNORECASE)
    RE_MZ = re.compile(br'MZ')   # binary search
    
    def __init__(self, filename):
        self.filename = filename
    
    def run(self) -> IocReport:
        if not os.path.isfile(self.filename):
            print('ERROR: file not found:', self.filename, file=sys.stderr); sys.exit(2)

        try:
            streams = self.list_streams_ooxml(self.filename)
        except Exception as e:
            print('ERROR reading OOXML file:', e, file=sys.stderr)
            streams = self.list_streams_fallback(self.filename)

        stream_results = []
        for name, data in streams:
            res = self.analyze_zip_stream(name, data)
            stream_results += res

        report = aggregate_report(stream_results)

        return report

    
    def analyze_zip_stream(self, name: str, data: bytes):
        hits = []

        # OLE objects embedded in OOXML
        if name.lower().startswith(('word/embeddings/', 'xl/embeddings/', 'ppt/embeddings/')):
            hits.append(IocHit(name='embedded_ole_object', description=f'Embedded OLE: {name}', hits=1, score=50))

        # Binary signature checks (MZ, PK, ELF, etc.)
        if self.RE_MZ.search(data):
            hits.append(IocHit(name='embedded_executable', description=f'{name} contains MZ executable', hits=1, score=80))

        # high entropy
        ent = entrophy_scan(data)
        if ent >= OoxmlPipeline.ENTROPY_THRESHHOLD:
            hit = {}
            hit['name'] = 'high_entropy'
            hit['description'] = f'High entropy of {ent} detected in one of OOXML streams which can indicate raw binary data embedded into the document'
            hit['hits'] = 1
            hit['score'] = 10
            hits.append(IocHit(**hit))
        
        # XML text content: decode and process for macro/network/obfuscation
        if name.endswith(('.xml', '.rels', '.txt')):
            text = data.decode('utf-8', errors='replace')
            hits += self.score_stream_texts(text)

        return hits

    def list_streams_ooxml(self, path: str):
        streams = []
        with zipfile.ZipFile(path, 'r') as z:
            for name in z.namelist():
                try:
                    data = z.read(name)
                except KeyError:
                    data = b''
                streams.append((name, data))
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
        
        if OoxmlPipeline.RE_EMBED_EXE.search(text):
            fnames = list(set(OoxmlPipeline.RE_EMBED_EXE.findall(text)))

            hits.append(IocHit(
                name='embedded_filename',
                description=f'Embedded filenames are detected: {fnames}',
                score=40,
                hits=len(OoxmlPipeline.RE_EMBED_EXE.findall(text))
            ))
            
        return hits