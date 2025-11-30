import os
import sys
from pypdf import PdfReader
from typing import List, Set
import re
from .. import IocHit, IocReport, Pipeline
from . import aggregate_report, entrophy_scan, js_scan, macro_scan, network_scan, obfuscation_scan
from pypdf.generic import IndirectObject, StreamObject, DictionaryObject

class PdfPipeline(Pipeline):
    ENTROPY_THRESHOLD = 7.5
    RE_EMBED_EXE = re.compile(r'[\w\-\./ ]+\.(exe|dll|scr|bat|ps1|js|vbs)', re.IGNORECASE)
    RE_MZ = re.compile(br'MZ')

    def __init__(self, filename):
        self.filename = filename

    def run(self) -> IocReport:
        if not os.path.isfile(self.filename):
            print('ERROR: file not found:', self.filename, file=sys.stderr); sys.exit(2)

        streams = self.extract_pdf_streams(self.filename)
        stream_results = []

        for data in streams:
            stream_results += self.analyze_stream(data, self.ENTROPY_THRESHOLD)
            
        stream_results += self.analyze_raw(self.filename)

        return aggregate_report(stream_results)
    
    def recursive_extract(self, obj, reader, streams: List[bytes], visited: Set[tuple]):
        """
        Recursively walk PDF objects, dereference indirects, collect stream bytes,
        and avoid visiting the same object multiple times.
        """
        # If it's an IndirectObject, check visited
        if isinstance(obj, IndirectObject):
            key = (obj.idnum, obj.generation)
            if key in visited:
                return
            visited.add(key)
            obj = reader.get_object(obj)  # dereference

        if isinstance(obj, StreamObject):
            try:
                streams.append(obj.get_data())
            except Exception:
                pass
            # still recurse into dictionary part of stream
            obj_dict = DictionaryObject(obj)
            for k, v in obj_dict.items():
                self.recursive_extract(v, reader, streams, visited)

        elif isinstance(obj, DictionaryObject):
            for k, v in obj.items():
                self.recursive_extract(v, reader, streams, visited)

        elif isinstance(obj, list):
            for element in obj:
                self.recursive_extract(element, reader, streams, visited)
                
    def extract_pdf_streams(self, path: str) -> List[bytes]:
        reader = PdfReader(path)
        list(reader.pages)  # force loading
        streams: List[bytes] = []
        visited: Set[int] = set()

        # Work on a snapshot of resolved objects
        objects = list(reader.resolved_objects.values())
        for obj in objects:
            self.recursive_extract(obj, reader, streams, visited)
            
        return streams

    def analyze_raw(self, path: str) -> List[IocHit]:
        with open(path, 'r', encoding="utf-8", errors="replace") as f:
            data = "\n".join(f.readlines())
            return self.score_stream_texts(data)

    def analyze_stream(self, data: bytes, threshold: int) -> List[IocHit]:
        hits = []
        if self.RE_MZ.search(data):
            hits.append(IocHit(name='embedded_MZ',
                              description='Embedded MZ binary likely present',
                              hits=len(self.RE_MZ.findall(data)),
                              score=40))

        if b'PK\x03\x04' in data:
            hits.append(IocHit(name='embedded_PK_zip',
                              description='Embedded zip (PK) detected',
                              hits=len(re.compile(b'PK\x03\x04').findall(data)),
                              score=20))

        ent = entrophy_scan(data)
        if ent >= threshold:
            hits.append(IocHit(name='high_entropy',
                              description=f'High entropy {ent} in PDF stream',
                              hits=1,
                              score=10))

        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            text = data.decode('latin-1', errors='replace')

        hits += self.score_stream_texts(text)
        return hits

    def score_stream_texts(self, text: str) -> List[IocHit]:
        hits = []
        hits += js_scan(text)
        hits += network_scan(text)

        if self.RE_EMBED_EXE.search(text):
            fnames = set(self.RE_EMBED_EXE.findall(text))
            hits.append(IocHit(name='embedded_filename',
                              description=f'Embedded filenames detected: {fnames}',
                              score=40,
                              hits=len(fnames)))
        return hits
