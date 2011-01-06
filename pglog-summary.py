#!/usr/bin/env python
#
#

import sys
import re
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
  for file in args:
    log_events = []
    error_events = []
    warn_events = []
    hint_events = []
    fatal_events = []
    unknown_events = []

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
        hint_events.append(entry)
      elif type == 'FATAL:':
        fatal_events.append(entry)
      else:
        unknown_events.append(entry)

    events = aggregate(unknown_events)
    print "\n=================="
    print "unknown events"
    print "==================\n"
    for val in events:
      print str(val)

    events = aggregate(fatal_events)
    print "\n=================="
    print "FATAL events"
    print "==================\n"
    for val in events:
      print str(val)

    events = aggregate(error_events)
    print "\n=================="
    print "ERROR events"
    print "==================\n"
    for val in events:
      print str(val)
      if val.total() > 200:
        print "\t[Sample]"
        for line in str(val.get_sample()).split("\n"):
          print "\t\t"+line
        print ""

    events = aggregate(warn_events)
    print "\n=================="
    print "WARNING events"
    print "==================\n"
    for val in events:
      print str(val)

    events = aggregate(log_events)
    print "\n=================="
    print "LOG events"
    print "==================\n"
    for val in events:
      print str(val)

aggregate_patterns = [
  { 'pattern': re.compile('^checkpoint complete:'),        'msg': 'checkpoint complete' },
  { 'pattern': re.compile('^automatic analyze of table '), 'msg': 'automatic analyze of table' },
  { 'pattern': re.compile('^automatic vacuum of table '),  'msg': 'automatic vacuum of table' },
  { 'pattern': re.compile('^duration: '),                  'msg': 'slow query' },
]

class Aggregate(object):
  def __init__(self, msg):
    self.msg = msg
    self.entries_by_ip = {}

  def add_entry(self, entry):
    if self.entries_by_ip.has_key(entry.ip):
      self.entries_by_ip[entry.ip].append(entry)
    else:
      self.entries_by_ip[entry.ip] = [entry]

  def total(self):
    total = 0
    for ip, entries in self.entries_by_ip.items():
      total += len(entries)
    return total

  def get_sample(self):
    longest = []
    for ip, entries in self.entries_by_ip.items():
      if len(longest) < len(entries):
        longest = entries
    return entries[0]

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

def aggregate(list_of_entries):
   msgs = {}
   for entry in list_of_entries:
     key = sanitize(entry)
     if not msgs.has_key(key):
       msgs[key] = Aggregate(key)
     msgs[key].add_entry(entry)
   events = [ m for m in msgs.values() ]
   events.sort(lambda x,y: y.total()-x.total())
   return events

def main():
  parser = OptionParser()
  (options, args) = parser.parse_args()
  if len(args) == 0:
    print "missing input file name"
    sys.exit(1)
  else:
    process_log(options, args)

if __name__ == "__main__":
  main()
