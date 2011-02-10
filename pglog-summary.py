#!/usr/bin/env python
#
#

import sys
import re
import gzip
from optparse import OptionParser

entry_start_re = re.compile("^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}")

class Entry(object):
  def __init__(self, ts, ip, db, type, msg):
    self.ts = ts
    self.ip = ip
    self.db = db
    self.type = type
    self.msg = msg

  def __str__(self):
    ret = '%s %s %s %s %s' % (self.ts, self.ip, self.db, self.type, self.msg)
    try:
      ret = '\n'.join([ret, str(self.context)])
    except AttributeError:
      pass
    try:
      ret = '\n'.join([ret, str(self.hint)])
    except AttributeError:
      pass
    try:
      ret = '\n'.join([ret, str(self.statement)])
    except AttributeError:
      pass
    try:
      ret = '\n'.join([ret, str(self.detail)])
    except AttributeError:
      pass
    return ret

def is_entry_start(line):
  """ assume postgres log entry starts with:
      yyyy-MM-dd hh:mm:dd
  """
  return entry_start_re.search(line)

def parse_raw_entry(raw_entry):
  """ Parses raw entry from the log file
      Assume the logging is configured with

      log_line_prefix = '%t %h %d '
  """
  entry_start = raw_entry[0]

  # get the timestamp
  ts_len = 23
  ts = entry_start[:ts_len]
  # get the IP, if there is one
  idx = entry_start.find(' ', ts_len+1)
  ip = entry_start[ts_len+1:idx]
  # get the database, if there is one
  consumed = idx
  idx = entry_start.find(' ', consumed+1)
  db = entry_start[consumed+1:idx]
  # get the log type
  consumed = idx
  idx = entry_start.find(' ', consumed+1)
  type = entry_start[consumed+1:idx]
  # finally, combined the message
  consumed = idx
  remaining = entry_start[consumed+1:]
  foo = [remaining]
  foo.extend(raw_entry[1:])
  msg = ''.join(foo).strip()

  return Entry(ts, ip, db, type, msg)
  
def get_entries(file):
  if file.endswith('.gz'):
    fh = gzip.open(file, "rb")
  else:
    fh = open(file)
  raw_entry = []
  for line in fh:
    if is_entry_start(line):
      if len(raw_entry) > 0:
        yield parse_raw_entry(raw_entry)
      # reset raw_entry
      raw_entry = [ line ]
    else:
      raw_entry.append(line)

def process_log(options, args):
  rval = 0
  output = ''
  for file in args:
    fatal_events = LevelQueue("FATAL")
    error_events = LevelQueue("ERROR")
    warn_events = LevelQueue("WARN")
    log_events = LevelQueue("LOG")
    unknown_events = LevelQueue("UNKNOWN")

    last_entry_by_ip = {}
    last_checkpoint_start = None

    for entry in get_entries(file):
      type = entry.type
      if type == 'LOG:':
        if entry.msg.startswith('checkpoint starting:'):
           last_checkpoint_start = entry
           continue
        if entry.msg.startswith('checkpoint complete:'):
           entry.detail = last_checkpoint_start
           last_checkpoint_start = None
        log_events.append(entry)
        last_entry_by_ip[entry.ip] = entry
      elif type == 'WARNING:':
        warn_events.append(entry)
      elif type == 'ERROR:':
        error_events.append(entry)
        last_entry_by_ip[entry.ip] = entry
      elif type == 'CONTEXT:':
        last_entry_by_ip[entry.ip].context = entry
      elif type == 'STATEMENT:':
        last_entry_by_ip[entry.ip].statement = entry
      elif type == 'DETAIL:':
        last_entry_by_ip[entry.ip].detail = entry
      elif type == 'HINT:':
        last_entry_by_ip[entry.ip].hint = entry
      elif type == 'FATAL:':
        fatal_events.append(entry)
      else:
        unknown_events.append(entry)

    def print_sample(out, agg):
      out += "\t[Sample]\n"
      for line in str(agg.get_sample()).split("\n"):
        out += "\t\t"+line+"\n"
      out += "\n"
      return out

    events = unknown_events.get_events()
    output += "\n==================\n"
    output += "unknown events\n"
    output += "==================\n\n"
    for val in events:
      output += str(val)+"\n"

    events = fatal_events.get_events()
    output += "\n==================\n"
    output += "FATAL events\n"
    output += "==================\n\n"
    for val in events:
      output += str(val)+"\n"
      if val.total() >= options.fatal_threshold:
        output = print_sample(output, val)
        rval += 1

    events = error_events.get_events()
    output += "\n==================\n"
    output += "ERROR events\n"
    output += "==================\n\n"
    for val in events:
      output += str(val)+"\n"
      if val.total() >= options.error_threshold and \
        not (options.suppress_dup_key and val.msg.startswith('duplicate key value violates unique constraint')):
        output = print_sample(output, val)
        rval += 1

    events = warn_events.get_events()
    output += "\n==================\n"
    output += "WARNING events\n"
    output += "==================\n\n"
    for val in events:
      output += str(val)+"\n"
      if val.total() >= options.warn_threshold:
        output = print_sample(output, val)
        rval += 1

    events = log_events.get_events()
    output += "\n==================\n"
    output += "LOG events\n"
    output += "==================\n\n"
    for val in events:
      output += str(val)+"\n"
      if val.total() >= options.log_threshold:
        output = print_sample(output, val)
        rval += 1

    return rval, output

aggregate_patterns = [
  { 'pattern': re.compile('^checkpoint complete:'),        'msg': 'checkpoint complete' },
  { 'pattern': re.compile('^automatic analyze of table '), 'msg': 'automatic analyze of table' },
  { 'pattern': re.compile('^automatic vacuum of table '),  'msg': 'automatic vacuum of table' },
  { 'pattern': re.compile('^duration: '),                  'msg': 'slow query' },
]

class Aggregate(object):
  num_sample_entries = 1
  def __init__(self, msg):
    self.msg = msg
    self.sample_entries = []
    self.cur_total = 0

  def add_entry(self, entry):
    if len(self.sample_entries) <= self.num_sample_entries:
      self.sample_entries.append(entry)
    self.cur_total += 1

  def total(self):
    return self.cur_total

  def get_sample(self):
    return self.sample_entries[0]

  def __str__(self):
    str = "%10d\t%s" % (self.total(), self.msg)
    return str

def sanitize(entry):
  key = entry.msg
  if entry.msg.startswith('execute '):
    # erase the context
    idx = entry.msg.find(':')
    key = 'execute NUM'+entry.msg[idx:]
  for ptn in aggregate_patterns:
    if ptn['pattern'].search(entry.msg):
      key = ptn['msg']
  return key

class LevelQueue(object):
  def __init__(self, name):
    self.name = name
    self.msgs = {}

  def append(self, entry):
    key = sanitize(entry)
    if not self.msgs.has_key(key):
       self.msgs[key] = Aggregate(key)
    self.msgs[key].add_entry(entry)

  def get_events(self):
   events = [ m for m in self.msgs.values() ]
   events.sort(lambda x,y: y.total()-x.total())
   return events

def main():
  parser = OptionParser()

  # sample-showing threshold
  parser.add_option("-e", "--error-threshold", dest="error_threshold",
                    type="int", default=200,
                    help="threshold of occurrences to start showing sample and return non-zero exit status (default 200)")
  parser.add_option("-f", "--fatal-threshold", dest="fatal_threshold",
                    type="int", default=1,
                    help="threshold of occurrences to start showing sample and return non-zero exit status (default 1)")
  parser.add_option("-w", "--warn-threshold", dest="warn_threshold",
                    type="int", default=2000,
                    help="threshold of occurrences to start showing sample and return non-zero exit status (default 2000)")
  parser.add_option("-l", "--log-threshold", dest="log_threshold",
                    type="int", default=1000000,
                    help="threshold of occurrences to start showing sample and return non-zero exit status (default 1M)")

  # ignore threshold options
  parser.add_option("--suppress-dup-key",
                    action="store_true", dest="suppress_dup_key", default=False,
                    help="suppress duplicate key value violations from triggered events")
  
  (options, args) = parser.parse_args()
  if len(args) == 0:
    print "missing input file name"
    sys.exit(1)
  else:
    rval, output = process_log(options, args)
    output = "".join(["\n%d event(s) exceed the threshold\n" % (rval), output])
    print output
    sys.exit(rval)

if __name__ == "__main__":
  main()

