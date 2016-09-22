# Interactive command line tool for fast TCP stream processing

*streams* is a tool for browsing, mining and processing TCP streams in pcap files. It provides a command line prompt for filtering, selecting and dumping reassembled session data. It can further invoke external tools to pipe stream data through. Here is the output of an example session:


```
$ /opt/streams/bin/streams
                                  _
              _____ _____     ___| |_ _ __ ___  __ _ _ __ ___  ___
   _____     |_____|_____|   / __| __| '__/ _ \/ _` | '_ ` _ \/ __|
  |_____| _  |_____|_____|   \__ \ |_| | |  __/ (_| | | | | | \__ \  _   _ _
       (_|_)____        (_)  |___/\__|_|  \___|\__,_|_| |_| |_|___/ (_) (_|_)
          |_____|
                      version 0.1.2, Copyright (C) 2011-2016 by Tillmann Werner

streams> help

  analyze	analyze trace file
  bpf		specify a berkeley packet filter expression
  count		display number of streams
  dump		dump selected stream to a file (see outfile)
  ext		specify external program (+ arguments) to pipe streams through (see pipe)
  filter	toggle stream filter status (include/exclude empty and incomplete streams)
  help		show help (this output)
  list		list streams
  match		specify a content pattern, use 'x [pattern]' for patterns in hexadecimal encoding
  offset	set datalink layer offset for packet trace file
  outfile	specify an output file for stream dumps (see dump)
  pipe		pipe selected stream through an external program (see ext)
  quit		quit program
  status	display program status
  timestamps	toggle time display format (absolute/relative)
  timeout	set tcp session timeout (needed to detect port reuse)

streams> analyze /tmp/http.pcap 
file processed, 4 streams (2 non-empty and complete).
streams> list
    2:       0.042225      40.832919  92.123.68.42:80 > 192.168.178.47:56628 (7484 bytes)
    3:       0.042321      44.841711  92.123.68.42:80 > 192.168.178.47:56630 (7397 bytes)
streams> filter
stream filter: off (list all streams)
streams> list
    0:       0.000000      40.873249  192.168.178.47:56628 > 92.123.68.42:80 (137 bytes) [incomplete]
    1:       0.000436      44.889474  192.168.178.47:56630 > 92.123.68.42:80 (137 bytes) [incomplete]
    2:       0.042225      40.832919  92.123.68.42:80 > 192.168.178.47:56628 (7484 bytes)
    3:       0.042321      44.841711  92.123.68.42:80 > 192.168.178.47:56630 (7397 bytes)
streams> ext hd
streams> pipe 0
00000000  47 45 54 20 2f 63 67 69  2d 62 69 6e 2f 6d 67 65  |GET /cgi-bin/mge|
00000010  74 6d 65 74 61 72 2e 70  6c 3f 63 63 63 63 3d 55  |tmetar.pl?cccc=U|
00000020  55 44 44 20 48 54 54 50  2f 31 2e 31 0d 0a 48 6f  |UDD HTTP/1.1..Ho|
00000030  73 74 3a 20 77 65 61 74  68 65 72 2e 6e 6f 61 61  |st: weather.noaa|
00000040  2e 67 6f 76 0d 0a 0d 0a  47 45 54 20 2f 6d 67 65  |.gov....GET /mge|
00000050  74 6d 65 74 61 72 2e 70  68 70 3f 63 63 63 63 3d  |tmetar.php?cccc=|
00000060  55 55 44 44 20 48 54 54  50 2f 31 2e 31 0d 0a 48  |UUDD HTTP/1.1..H|
00000070  6f 73 74 3a 20 77 65 61  74 68 65 72 2e 6e 6f 61  |ost: weather.noa|
00000080  61 2e 67 6f 76 0d 0a 0d  0a                       |a.gov....|
00000089
streams> outfile /tmp/streams.bin
streams> dump 3
7397 bytes written to /tmp/streams.bin
streams> match Moved
applying new match expression...
streams> list
    2:       0.042225      40.832919  92.123.68.42:80 > 192.168.178.47:56628 (7484 bytes)
    3:       0.042321      44.841711  92.123.68.42:80 > 192.168.178.47:56630 (7397 bytes)
streams> bpf tcp port 56628
applying new filter...
file processed, 2 streams (1 non-empty and complete).
streams> list
    1:       0.042225      40.832919  92.123.68.42:80 > 192.168.178.47:56628 (7484 bytes)
streams> match
match expression removed
streams> list
    0:       0.000000      40.873249  192.168.178.47:56628 > 92.123.68.42:80 (137 bytes) [incomplete]
    1:       0.042225      40.832919  92.123.68.42:80 > 192.168.178.47:56628 (7484 bytes)
streams> quit
$
```


streams is (C) 2011-2016 by Tillmann Werner
