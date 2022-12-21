import os

os.mkdir('ip_folder')

"""import sqlite3
import time
import os

conn = sqlite3.connect('node_bills.db')

cur = conn.cursor()
pos1 = ['1x', '2x', '5x', '10x', '20x', '50x', '100x', '200x', '500x', '1000x', '2000x', '5000x', '10000x', '20000x', '50000x', '100000x']
m = ['5x87', '1x0']
s = time.perf_counter()
finder_range = []
for cou in range(50):
    finder_range.append('100x' + str(cou))
cur.execute("SELECT * FROM bills WHERE serial_num IN (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", tuple(finder_range))

print(cur.fetchall())
pos = ['1x', '2x', '5x', '10x', '20x', '50x', '100x', '200x', '500x', '1000x', '2000x', '5000x', '10000x',
       '20000x', '50000x', '100000x']
for x in pos:
    for c in range(100):
        cur.execute("INSERT INTO bills VALUES(?, ?, ?)", (x + str(c), 'x15FJEWNpLNw8dp58bK4Hg4mmywznx', '0'))

e = time.perf_counter()
print(e - s)
conn.commit()
conn.close()
"""