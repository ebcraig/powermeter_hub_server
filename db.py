"""Module for logging time series data to sqlite."""
import logging
import time
from prometheus_client import start_http_server, Gauge
import sqlite3

def SetupDb(path):
  global powerGauge
  powerGauge = Gauge('power_demand', 'Power demand in wH')
  start_http_server(8000)

def LogData(label, value, timestamp=-1):
  """Log an event/value pair.

  Args:
    label: (str) The type of data being logged.
    value: (float) The value to be logged.
    timestamp: (int) Optional timestamp (seconds since epoch).
  Returns:
    None
  """
  global powerGauge
  powerGauge.set(value)

# Cache of label to ID mappings.
LogData._labels = {}
