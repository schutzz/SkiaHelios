from abc import ABC, abstractmethod
import polars as pl
import re

class BaseDetector(ABC):
    def __init__(self, config: dict):
        self.config = config

    @abstractmethod
    def analyze(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        Analyze the timeline DataFrame and apply scoring/tagging rules.
        Must allow streaming-compatible operations where possible.
        """
        pass

    def _get_column_or_default(self, df: pl.DataFrame, col_name: str, default_val="") -> str:
        if col_name in df.columns:
            return col_name
        return default_val
