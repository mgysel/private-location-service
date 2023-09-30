import re

filename = "network_trace_test.txt"
textfile = open(filename, 'r')
filetext = textfile.read()
textfile.close()
matches = re.findall(r'length \d+', filetext)
for i in range(len(matches)):
    matches[i] = int(matches[i][7:])
print(matches)