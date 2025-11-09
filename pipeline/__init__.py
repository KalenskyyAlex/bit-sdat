from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import List, Optional

@dataclass
class IocHit:
    score: int
    hits: int
    name: str
    description: Optional[str]

@dataclass
class IocReport:
    hits: List[IocHit]

class Pipeline(ABC):
    @abstractmethod
    def run(self) -> IocReport:
        ...
        