import matplotlib.pyplot as plt

data = {'ahnlab': {'seg': 3, 'vis': 44}, 'bitdefender': {'seg': 3, 'vis': 47}, 'checkpoint': {'seg': 3, 'vis': 47}, 'cisco': {'seg': 3, 'vis': 45}, 'crowdstrike': {'seg': 3, 'vis': 47}, 'cybereason': {'seg': 3, 'vis': 47}, 'cycraft': {'seg': 3, 'vis': 35}, 'cylance': {'seg': 3, 'vis': 44}, 'cynet': {'seg': 3, 'vis': 47}, 'deepinstinct': {'seg': 7, 'vis': 36}, 'elastic': {'seg': 3, 'vis': 45}, 'eset': {'seg': 3, 'vis': 41}, 'fidelis': {'seg': 3, 'vis': 43}, 'fireeye': {'seg': 3, 'vis': 40}, 'fortinet': {'seg': 3, 'vis': 47}, 'malwarebytes': {'seg': 3, 'vis': 43}, 'mcafee': {'seg': 3, 'vis': 46}, 'microsoft': {'seg': 3, 'vis': 41}, 'paloaltonetworks': {'seg': 3, 'vis': 47}, 'qualys': {'seg': 3, 'vis': 38}, 'rapid7': {'seg': 9, 'vis': 25}, 'reaqta': {'seg': 3, 'vis': 41}, 'sentinelone': {'seg': 3, 'vis': 47}, 'somma': {'seg': 3, 'vis': 38}, 'sophos': {'seg': 3, 'vis': 41}, 'symantec': {'seg': 3, 'vis': 41}, 'trendmicro': {'seg': 3, 'vis': 46}, 'uptycs': {'seg': 3, 'vis': 44}, 'vmware': {'seg': 3, 'vis': 43}, 'withsecure': {'seg': 3, 'vis': 36}}

seg = [data[key]['seg'] for key in data.keys()]
vis = [data[key]['vis'] for key in data.keys()]

plt.scatter(seg, vis)
plt.xlabel('seg')
plt.ylabel('vis')
plt.show()