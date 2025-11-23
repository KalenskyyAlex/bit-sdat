from collections import Counter
import math
import re
from typing import List
from .. import IocHit

RE_AUTO_MACRO = re.compile(r'\b(AutoOpen|AutoExec|Document_Open|Workbook_Open|Auto_Open)\b', re.IGNORECASE)
RE_SHELL_CALL = re.compile(r'\b(CreateObject|ShellExecute|Shell\(|WScript\.|Run\(|cmd\.exe|powershell|mshta|osascript)\b', re.IGNORECASE)
RE_URL = re.compile(r'https?://[^\s\'"<>]{5,}|ftp://[^\s\'"<>]{5,}', re.IGNORECASE)
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_BASE64_CAND = re.compile(r'(?:[A-Za-z0-9+/]{40,}={0,2})')

def entrophy_scan(data: bytes):
    if not data:
        return 0.0
    
    counts = Counter(data)
    length = len(data)
    ent = -sum((c/length) * math.log2(c/length) for c in counts.values())
    return ent

def macro_scan(text: str) -> List[IocHit]:
    hits = []
    
    if RE_AUTO_MACRO.search(text):
        hits.append(IocHit(
            name='auto_macro',
            description='Suspisious macros are detected',
            score=50,
            hits=len(RE_AUTO_MACRO.findall(text))
        ))
    if RE_SHELL_CALL.search(text):
        hits.append(IocHit(
            name='shell_call',
            description='Shell calls are detected',
            score=20,
            hits=len(RE_SHELL_CALL.findall(text))
        ))
        
    return hits

def network_scan(text: str) -> List[IocHit]:
    hits = []
    
    if RE_URL.search(text) or RE_IP.search(text):
        urls = list(set(RE_URL.findall(text)))
        ips = list(set(RE_IP.findall(text)))
        
        hits.append(IocHit(
            name='network_indicator',
            description=f'Network indicators are detected: URLs: {urls}, IPs: {ips}',
            score=15,
            hits=len(RE_URL.findall(text)) + len(RE_IP.findall(text))
        ))
        
    return hits

def obfuscation_scan(text: str) -> List[IocHit]:
    hits = []
    
    if RE_BASE64_CAND.search(text):
        b64s = list(set(RE_BASE64_CAND.findall(text)))[:3]  # cap for brevity

        hits.append(IocHit(
            name='base64_candidate',
            description=f'Base64 candidates found (which could be a way to obfuscate content): {b64s}, ...',
            score=15,
            hits=len(RE_BASE64_CAND.findall(text))
        ))
        
    return hits
    