from typing import List
from .. import IocHit, IocReport, Pipeline
import sys, os, io, json, math, re, argparse, base64, binascii
from . import entrophy_scan
import olefile


class CfbfPipeline(Pipeline):
    ENTROPY_THRESHHOLD = 7
    RE_AUTO_MACRO = re.compile(r'\b(AutoOpen|AutoExec|Document_Open|Workbook_Open|Auto_Open)\b', re.IGNORECASE)
    RE_SHELL_CALL = re.compile(r'\b(CreateObject|ShellExecute|Shell\(|WScript\.|Run\(|cmd\.exe|powershell|mshta|osascript)\b', re.IGNORECASE)
    RE_URL = re.compile(r'https?://[^\s\'"<>]{5,}|ftp://[^\s\'"<>]{5,}', re.IGNORECASE)
    RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    RE_EMBED_EXE = re.compile(r'[\w\-\./ ]+\.(exe|dll|scr|bat|ps1|js|vbs)', re.IGNORECASE)
    RE_BASE64_CAND = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')
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

        report = self.aggregate_report(stream_results)

        print(report)

    
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
            hit['name'] = 'embedded_MZ'
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
        if CfbfPipeline.RE_AUTO_MACRO.search(text):
            hits.append(IocHit(
                name='auto_macro',
                description='Suspisious macros are detected',
                score=50,
                hits=len(CfbfPipeline.RE_AUTO_MACRO.findall(text))
            ))
        if CfbfPipeline.RE_SHELL_CALL.search(text):
            hits.append(IocHit(
                name='shell_call',
                description='Shell calls are detected',
                score=20,
                hits=len(CfbfPipeline.RE_SHELL_CALL.findall(text))
            ))
        if CfbfPipeline.RE_URL.search(text) or CfbfPipeline.RE_IP.search(text):
            urls = list(set(CfbfPipeline.RE_URL.findall(text)))
            ips = list(set(CfbfPipeline.RE_IP.findall(text)))
            
            hits.append(IocHit(
                name='network_indicator',
                description=f'Network indicators are detected: URLs: {urls}, IPs: {ips}',
                score=15,
                hits=len(CfbfPipeline.RE_URL.findall(text)) + len(CfbfPipeline.RE_IP.findall(text))
            ))
        if CfbfPipeline.RE_EMBED_EXE.search(text):
            fnames = list(set(CfbfPipeline.RE_EMBED_EXE.findall(text)))

            hits.append(IocHit(
                name='embedded_filename',
                description=f'Embedded filenames are detected: {fnames}',
                score=40,
                hits=len(CfbfPipeline.RE_EMBED_EXE.findall(text))
            ))
        if CfbfPipeline.RE_BASE64_CAND.search(text):
            b64s = list(set(CfbfPipeline.RE_BASE64_CAND.findall(text)))[:3]  # cap for brevity
            
            hits.append(IocHit(
                name='base64_candidate',
                description=f'Base64 candidates found (which could be a way to obfuscate content): {b64s}, ...',
                score=15,
                hits=len(CfbfPipeline.RE_BASE64_CAND.findall(text))
            ))
            
        return hits
    
    def aggregate_report(self, stream_results: List[IocHit]) -> IocReport:
        total_score = 0
        for s in stream_results:
            total_score += s.score * s.hits
            
        report = {
            'hits': stream_results,
            'total_score': total_score,
            'verdict': 'unknown'
        }
        
        if any(s.score >= 50 for s in stream_results):
            report['verdict'] = 'high_risk'
        elif any(s.score >= 25 for s in stream_results):
            report['verdict'] = 'medium_risk'
        else:
            report['verdict'] = 'low_risk'
            
        return IocReport(**report)

