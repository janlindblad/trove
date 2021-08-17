#!/usr/bin/env python3
# Trove -- NSO Trace Overview
#
# (C) 2021 Cisco Systems
# Written by Jan Lindblad <jlindbla@cisco.com>

import sys, os, getopt

class Trove:
  inmarker  = "<<<<in"
  outmarker = ">>>>out"

  def __init__(self):
    self.expansions = []
    self.debug = False

  def add_expansion(self, exp):
    self.expansions += [exp]

  def expand_match(self, message, lineno=0):
    if self.debug: print(f"*** expand_match({message if lineno else message.get('type')}, {lineno})")
    # %edit-config
    # %edit-config;/sr/traffic-engineering
    def match_one_exp(exp, message):
      def match_one_cmd(cmd, message):

        def match_path(req_path, line):
          if self.debug: print(f"*** match_path({req_path}, {line}) {self.tag_stack}")
          for depth, tag in enumerate(req_path,2):
            if tag != self.tag_stack.get(depth, None):
              if self.debug: print(f"*** match_path() False {depth}: {tag} in {req_path} vs. {self.tag_stack}")
              return False
          if self.debug: print(f"*** match_path() True {depth}: {tag} in {req_path} vs. {self.tag_stack}")
          return True

        def get_tag_depth(s):
          def count_leading_spaces(s):
            for n,c in enumerate(s,0):
              if c != " ":
                return n
            return len(s)
          def count_identifier_chars(s):
            for n,c in enumerate(s,0):
              if c in " />":
                return n
            return len(s)
          leading_spaces = count_leading_spaces(s)
          if not s[leading_spaces:].startswith("<"):
            return (None, None)
          if s[leading_spaces+1:].startswith("/"):
            word = s[leading_spaces+2:]
          else:
            word = s[leading_spaces+1:]
          word_len = count_identifier_chars(word)
          word = word[:word_len]
          return (word, leading_spaces // 2)

        if not cmd:
          return True
        cmd, arg = cmd[0], cmd[1:]
        if lineno:
          (tag, depth) = get_tag_depth(message)
          if tag and depth:
            self.tag_stack[depth] = tag
          if cmd == '^': # top N levels
            if depth > int(arg):
              return False
          elif cmd == '#': # line number <= than this
            if lineno > int(arg):
              return False
          elif cmd == '!': # invert match
            res = match_one_cmd(arg, message)
            if self.debug: print(f"*** match_one(1) inverting result {res}")
            if res == None:
              return None
            return not res
          elif cmd == '/': # path match
            res = match_path(arg.split("/"), message)
            if self.debug: print(f"*** match_one(1) match path {arg} result {res}")
            return res
          elif cmd in "%": # Filter commands
            return None
          else:
            if self.debug: print(f"*** match_one(1) filter unknown {cmd}{arg}")
            return False
        else:
          self.tag_stack = {}
          if cmd == '%': # operation type, e.g. edit-config, hello, EOF
            if arg not in message.get('type',''):
              if self.debug: print(f"*** match_one(0) False: {arg} not in {message.get('type','')}")
              return False
          elif cmd == '!': # invert match
            res = match_one_cmd(arg, message)
            if self.debug: print(f"*** match_one(0) inverting result {res}")
            if res == None:
              return None
            return not res
          elif cmd in "#/^": # Filter commands
            return None
          else:
            if self.debug: print(f"*** match_one(0) cmd unknown {cmd}{arg}")
            return False
        return True

      conditions = exp.split(";")
      for cond in conditions:
        if self.debug: print(f"*** match_one() condition {cond}")
        res = match_one_cmd(cond, message)
        if res == None:
          continue
        if not res:
          if self.debug: print(f"*** match_one() False: condition failed")
          return False
      if self.debug: print(f"*** match_one() True: all conditions matched")
      return True

    for e in self.expansions:
      if self.debug: print(f"*** expand_match() testing {e} vs. {message if lineno else message.get('type','')}")
      if match_one_exp(e, message):
        if self.debug: print(f"*** expand_match() False")
        return True
    if self.debug: print(f"*** expand_match() True")
    return False

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
      if self.expand_match(m):
        for lineno,line in enumerate(m.get('body',[]),1):
          if self.expand_match(line,lineno=lineno):
            print(f"""       {lineno:10}:  {line}""")


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
      opts, args = getopt.getopt(sys_argv[1:],"hdve:",
        ["help", "debug=", "verbose", "expand="])
    except getopt.GetoptError:
      usage(sys_argv)
      sys.exit(2)
    for opt, arg in opts:
      if opt in ('-h', '--help'):
        usage(sys_argv)
        sys.exit()
      elif opt in ("-d", "--debug"):
        self.debug = True
      elif opt in ("-e", "--expand"):
        self.add_expansion(arg)
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
