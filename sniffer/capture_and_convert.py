import subprocess as sub

p = sub.Popen(('sudo', 'tcpdump', '-lvv'), stdout=sub.PIPE)
for row in iter(p.stdout.readline, b''):
    print (row.rstrip())