from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import List, Literal, Optional, Union

@dataclass
class IocHit:
    score: int
    hits: int
    name: str
    description: Optional[str]
    
    def to_dict(self):
        return {
            'name': self.name,
            'description': self.description,
            'score': self.score,
            'hits': self.hits
        }

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

@dataclass
class IocReport:
    hits: List[IocHit]
    total_score: int
    verdict: Union[Literal['low_risk'], Literal['medium_risk'], Literal['high_risk']]
    
    def to_dict(self):
        return {
            'verdict': self.verdict,
            'total_score': self.total_score,
            'hits': [ hit.to_dict() for hit in self.hits ]
        }

    @classmethod
    def from_dict(cls, d):
        d['hits'] = [IocHit.from_dict(hit) for hit in d['hits']]
        return cls(**d)

class Pipeline(ABC):
    @abstractmethod
    def run(self) -> IocReport:
        ...
        