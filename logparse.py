#!/usr/bin/env python3
"""logparse - Parse common log formats. Zero deps."""
import sys,re,collections
PATTERNS={'combined':r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]+" (\d+) (\d+)','syslog':r'(\w+\s+\d+\s+[\d:]+) (\S+) ([^:]+): (.*)'}
def main():
    fmt=sys.argv[1] if len(sys.argv)>1 else 'combined'
    pat=re.compile(PATTERNS.get(fmt,PATTERNS['combined']))
    status=collections.Counter();ips=collections.Counter();n=0
    for line in sys.stdin:
        m=pat.match(line)
        if m and fmt=='combined':
            ips[m.group(1)]+=1;status[m.group(5)]+=1;n+=1
    print(f'Lines: {n}')
    print('
Top IPs:');[print(f'  {c:>5} {ip}') for ip,c in ips.most_common(10)]
    print('
Status codes:');[print(f'  {c:>5} {s}') for s,c in status.most_common()]
if __name__=='__main__':main()
