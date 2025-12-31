"""
AI Matching Services Package

This package contains service classes for AI-powered matching operations:
- HybridRankingEngine: Implements the hybrid ATS ranking system (rules + AI + verification)
- Additional services for embedding generation, parsing, etc.
"""

from .ranking_engine import HybridRankingEngine

__all__ = [
    'HybridRankingEngine',
]
