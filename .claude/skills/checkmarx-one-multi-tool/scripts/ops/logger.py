"""Logging helper for ported scan/triage operations."""
import logging


def get_logger(name: str = "cxone.ops") -> logging.Logger:
    return logging.getLogger(name)
