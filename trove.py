#!/usr/bin/env python3
# Trove -- NSO Trace Overview
#
# (C) 2021 Cisco Systems
# Written by Jan Lindblad <jlindbla@cisco.com>

import sys, os, getopt

class Trove:
  inmarker  = "<<<<in"
  outmarker = ">>>>out"
  def print_trace_overview(self, trace_file_name):
    with open(trace_file_name, "r") as f:
      trace_text = f.read()
      overview = self.generate_trace_overview(trace_text)
    for mnum,m in enumerate(overview):
      mtype = m.get('type','')
      if m.get('unparsed'): mtype = 'UNPARSED ' + mtype
      if m.get('badxml'): mtype = 'BADXML ' + mtype
      if m.get('timeout'): mtype = 'TIMEOUT ' + mtype
      if m.get('close'): mtype = 'CLOSED ' + mtype
      if m.get('eof'): mtype = 'EOF ' + mtype
      print(f"""{mnum:3} {m['line-start']:4}+{m['length']:>5} {m['time']} {m.get('direction')} {m.get('message-id','')} {mtype}""")

  def generate_trace_overview(self, trace_text):
    overview = []
    message = {}
    summary = None
    for lineno,line in enumerate(trace_text.split('\n'),1):
      if line.startswith(Trove.outmarker) or line.startswith(Trove.inmarker):
        summary = self.generate_message_summary(lineno, message)
        message = self.parse_message_header(lineno, line)
      else:
        message['body'] = message.get('body',[])
        message['body'].append(line)
      if summary: 
        overview += [summary]
        summary = None
    return overview

  def parse_message_header(self, lineno, line):
    #>>>>out 30-Jun-2021::11:47:04.142 user: tsdn/95 thandle 1912 hostname tsdn-cicd device PE2
    #<<<<in 30-Jun-2021::11:47:04.293 user: tsdn/95 thandle 1912 hostname tsdn-cicd device PE2
    #>>>>out 30-Jun-2021::15:21:44.988 user: tsdn/7472 thandle 47447 hostname tsdn-cicd device PE2 session-id=1059273927
    #>>>>out 30-Jun-2021::15:21:44.989 user: tsdn/7472 thandle 47447 hostname tsdn-cicd device PE2 session-id=1059273927 NCS close
    hdr = {'line-start': lineno}
    words = line.split(' ')
    if words[0] == Trove.outmarker:
      hdr['direction'] = '-->'
    elif words[0] == Trove.inmarker:
      hdr['direction'] = '<--'
    else:
      print(f'Unparsed0: "{words[0]}"')
      hdr['unparsed'] = True
    hdr['timestamp'] = words[1]
    [hdr['date'],hdr['time']] = words[1].split('::')
    skip_args = 0
    for num,word in enumerate(words[2:],2):
      if skip_args:
        skip_args -= 1
        continue
      if word == 'user:':
        skip_args = 1
        hdr['user'] = words[num+1]
      elif word == 'thandle':
        skip_args = 1
        hdr['thandle'] = words[num+1]
      elif word == 'hostname':
        skip_args = 1
        hdr['hostname'] = words[num+1]
      elif word == 'device':
        skip_args = 1
        hdr['device'] = words[num+1]
      elif word.startswith('session-id='):
        session_id = word.split('=')[1]
        hdr['session-id'] = session_id
      elif word == 'NCS':
        if words[num+1] == 'close':
          skip_args = 1
          hdr['close'] = True
        else:
          print(f'Unparsed1: "{word}"')
          hdr['unparsed'] = True
      elif word == '(badxml)':
          hdr['badxml'] = True
      elif word == 'TIMEOUT':
          hdr['timeout'] = True
      elif word == 'EOF':
          hdr['eof'] = True
      else:
        print(f'Unparsed2: "{word}"')
        hdr['unparsed'] = True
    hdr['raw-header'] = line
    return hdr

  def generate_message_summary(self, lineno, message):
    def parse_message_id(mid_str):
      if not mid_str[0] == '"':
        return "?"
      return mid_str.split('"')[1]

    if not message:
      return None
    message['line-end'] = lineno - 1
    message['length'] = message['line-end'] - message['line-start'] + 1
    main_op = False
    for bodyline in message.get('body',[])[:10]:
      if "<hello " in bodyline:
        message['type'] = 'hello'
        break
      if "message-id=" in bodyline:
        message['message-id'] = parse_message_id(bodyline.split("message-id=")[1])
      if "<rpc " in bodyline or "<rpc-reply " in bodyline:
        main_op = True
        continue
      if main_op and bodyline.strip().startswith("<"):
        message['type'] = bodyline
        main_op = False
    return message

  def run_command_line(self, sys_argv=sys.argv):
    def usage(sys_argv):
      print(f'{sys_argv[0]} netconf-device.trace...')
    trace_files = []
    verbosity = 0
    debug = False
    try:
      opts, args = getopt.getopt(sys_argv[1:],"hd:v",
        ["help", "debug=", "verbose"])
    except getopt.GetoptError:
      usage(sys_argv)
      sys.exit(2)
    for opt, arg in opts:
      if opt in ('-h', '--help'):
        usage(sys_argv)
        sys.exit()
      elif opt in ("-d", "--debug"):
        debug = True
      elif opt in ("-v", "--verbose"):
        verbosity += 1
      else:
        Logger.fatal(f'Unknown option "{opt}".')
        sys.exit(2)

    trace_files = args
    if not trace_files:
      usage(sys_argv)
      sys.exit(2)
    for trace_file_name in trace_files:
      self.print_trace_overview(trace_file_name)

if ( __name__ == "__main__"):
  Trove().run_command_line()
