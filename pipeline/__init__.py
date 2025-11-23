from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import List, Literal, Optional, Union

@dataclass
class IocHit:
    score: int
    hits: int
    name: str
    description: Optional[str]

@dataclass
class IocReport:
    hits: List[IocHit]
    total_score: int
    verdict: Union[Literal['low_risk'], Literal['medium_risk'], Literal['high_risk']]

class Pipeline(ABC):
    @abstractmethod
    def run(self) -> IocReport:
        ...
        