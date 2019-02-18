"""Module for logging time series data to prometheus."""
import logging
from prometheus_client import start_http_server, Gauge
from time import time

def setup():
  global powerGauge
  global timeGauge
  global lastLog
  lastLog = -1
 
  timeGauge = Gauge('time_since_sample', 'Time (seconds) since last sample')
  powerGauge = Gauge('power_demand', 'Power demand in wH')
  start_http_server(8000)

def logData(label, value):
  """Log an event/value pair.

  Args:
    label: (str) The type of data being logged.
    value: (float) The value to be logged.
  Returns:
    None
  """
  global powerGauge
  global timeGauge
  global lastLog
  curTime = time()

  if lastLog is None:
    lastLog = curTime - 20
  
  timeGauge.set(curTime - lastLog)
  powerGauge.set(value)

logData._labels = {}
