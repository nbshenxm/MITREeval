import matplotlib.pyplot as plt
import numpy as np
from collections import Counter, OrderedDict

data = {'ahnlab': {'seg': 5, 'vis': 76, 'det': 56}, 'bitdefender': {'seg': 6, 'vis': 97, 'det': 97}, 'checkpoint': {'seg': 6, 'vis': 94, 'det': 94}, 'cisco': {'seg': 10, 'vis': 83, 'det': 69}, 'crowdstrike': {'seg': 6, 'vis': 95, 'det': 86}, 'cybereason': {'seg': 6, 'vis': 98, 'det': 97}, 'cycraft': {'seg': 6, 'vis': 73, 'det': 60}, 'cylance': {'seg': 11, 'vis': 83, 'det': 67}, 'cynet': {'seg': 6, 'vis': 96, 'det': 92}, 'deepinstinct': {'seg': 9, 'vis': 60, 'det': 56}, 'elastic': {'seg': 6, 'vis': 89, 'det': 68}, 'eset': {'seg': 5, 'vis': 68, 'det': 64}, 'fidelis': {'seg': 6, 'vis': 88, 'det': 80}, 'fireeye': {'seg': 6, 'vis': 82, 'det': 78}, 'fortinet': {'seg': 5, 'vis': 80, 'det': 79}, 'malwarebytes': {'seg': 5, 'vis': 75, 
'det': 75}, 'mcafee': {'seg': 6, 'vis': 96, 'det': 79}, 'microsoft': {'seg': 6, 'vis': 87, 'det': 87}, 'paloaltonetworks': {'seg': 6, 'vis': 96, 'det': 96}, 'qualys': {'seg': 5, 'vis': 63, 'det': 49}, 'rapid7': {'seg': 13, 'vis': 59, 'det': 23}, 'reaqta': {'seg': 6, 'vis': 65, 'det': 58}, 'sentinelone': {'seg': 6, 'vis': 97, 'det': 97}, 'somma': {'seg': 5, 'vis': 64, 'det': 28}, 'sophos': {'seg': 6, 'vis': 82, 'det': 64}, 'symantec': {'seg': 6, 'vis': 84, 'det': 79}, 'trendmicro': {'seg': 6, 'vis': 94, 'det': 89}, 'uptycs': {'seg': 6, 'vis': 86, 'det': 77}, 'vmware': {'seg': 6, 'vis': 81, 'det': 53}, 'withsecure': {'seg': 6, 'vis': 78, 'det': 62}}

seg = [data[key]['seg'] for key in data.keys()]
vis = [data[key]['vis'] for key in data.keys()]
det = [data[key]['det'] for key in data.keys()]
frequency = Counter(seg)
segs = frequency.keys()
freq = frequency.values()

seg_det_dict = {}
for s, d in zip(seg, det):
    if s in seg_det_dict:
        seg_det_dict[s].append(d)
    else:
        seg_det_dict[s] = [d]

ordered_seg_det_dict = OrderedDict(sorted(seg_det_dict.items()))
plt.boxplot(list(ordered_seg_det_dict.values()))
print(list(ordered_seg_det_dict.keys()))
plt.xticks(np.arange(1, len(ordered_seg_det_dict)+1), list(ordered_seg_det_dict.keys()))
plt.show()

# plt.scatter(seg, vis)
# plt.xlabel('seg')
# plt.ylabel('vis')
# plt.show()

# plt.scatter(seg, det)
# plt.xlabel('seg')
# plt.ylabel('det')
# plt.show()

# plt.bar(segs, freq)
# plt.xlabel('seg')
# plt.ylabel('freq')
# plt.xticks(np.arange(5,14, step=1))
# plt.yticks(np.arange(0,21,step=5))
# plt.show()
