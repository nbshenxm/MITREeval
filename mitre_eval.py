from fileinput import filename
import json, os, csv
import matplotlib.pyplot as plt
import numpy as np
import matplotlib.patches as mpatches
import matplotlib.ticker as plticker
from pprint import pprint
from numpy.core.numeric import NaN
import pandas as pd
from enum import Enum
from ref import StatsRef
import seaborn as sns
from graph import Graph

try:
    os.remove('results/vendor_results.json')
    os.remove('results/tactic_results.json')
    print("Deleting old result files...")
except:
    pass

if not os.path.exists(os.getcwd() + '/results'):
    os.makedirs(os.getcwd() + '/results')
if not os.path.exists(os.getcwd() + '/graphs'):
    os.makedirs(os.getcwd() + '/graphs')

pd.set_option("display.max_rows", None)
filenames = [f for f in os.listdir('json')]

r = StatsRef()
attacks, colors, evaluations, participants, countries, scoring, grading, detection_types, modifiers, participants_by_eval = r.get_references()
for e in evaluations:
    if not os.path.exists(os.getcwd() + f'/graphs/{e}'):
        os.makedirs(os.getcwd() + f'/graphs/{e}')

# technique_coverage = pd.DataFrame(columns=('Tactic', 'TechniqueName', 'Detection', 'Modifiers'))
# vendor_coverage = pd.DataFrame(columns=('Tactic', 'TechniqueName', 'Detection', 'Modifiers'))
technique_coverage = {}
vendor_protections = {}
datasources = {}
tactic_protections = {}

def crawl_results(filename):
    print(f'processing {filename}...')
    name_lst = filename.split('_')
    vendor = name_lst[0]
    rnd = name_lst[1]
    vendor_protections[vendor] = {}
    if rnd not in datasources.keys():
        datasources[rnd] = {}
    if rnd not in technique_coverage.keys():
        technique_coverage[rnd] = {}
    pdf = pd.DataFrame(columns=('Vendor', 'Adversary', 'Substep', 'Criteria', 'Tactic', 'TechniqueId', 'TechniqueName', 'SubtechniqueId', 'Detection', 'Modifiers'))
    with open('json/' + filename, 'r') as fp:
        data = json.load(fp)
        for elem in data['Adversaries']:
            if elem['Adversary_Name'] != rnd:
                continue
            tally = 0
            for ii in range(1, 3):
                for item in elem['Detections_By_Step'][f'Scenario_{ii}']['Steps']:
                    for substep in item['Substeps']:
                        tally += 1
                        obj = {'Vendor': vendor, 'Adversary': rnd, 'Substep':None, 'Criteria':None, 'Tactic':None, 'TechniqueId':None, 'TechniqueName':None, 'SubtechniqueId':None, 'Detection':None, 'Modifiers':None}
                        technique = substep['Technique']['Technique_Name']
                        tactic = substep['Tactic']['Tactic_Name']
                        if tactic not in technique_coverage[rnd].keys():
                            technique_coverage[rnd][tactic] = []
                        if technique not in technique_coverage[rnd][tactic]:
                            technique_coverage[rnd][tactic].append(technique)
                        detections = substep['Detections']
                        obj['Substep'] = substep['Substep']
                        obj['Criteria'] = substep['Criteria']
                        obj['Tactic'] = tactic
                        obj['TechniqueId'] = substep['Technique']['Technique_Id']
                        obj['TechniqueName'] = technique
                        obj['SubtechniqueId'] = substep['Subtechnique']['Subtechnique_Id']
                        ret = {'Detection_Type':'N/A', 'Modifiers':'', 'Indicator':'', 'Indicator_Name':''} 
                        dt = Enum('DetectionTypes', detection_types[rnd])
                        if substep['Substep'] not in datasources[rnd].keys():
                            datasources[rnd][substep['Substep']] = {}
                        for detection in detections:
                            detection_type = detection['Detection_Type'].replace(' ', '')
                            if dt[ret['Detection_Type'].replace(' ', '')].value < dt[detection_type].value:
                                ret = detection
                            # if vendor not in datasources[rnd].keys():
                            #     datasources[rnd][vendor] = {}
                            try:
                                for source in detection['Data_Sources']:
                                    try:
                                        datasources[rnd][substep['Substep']][source] += 1
                                    except KeyError:
                                        datasources[rnd][substep['Substep']][source] = 1
                                for item in detection['Screenshots']:
                                    for source in item['Data_Sources']:
                                        try:
                                            datasources[rnd][substep['Substep']][source] += 1
                                        except KeyError:
                                            datasources[rnd][substep['Substep']][source] = 1
                            except KeyError:
                                pass
                        try:
                            i = ret['Indicator']
                        except:
                            i = 'N/A'
                        try:
                            n = ret['Indicator_Name']
                        except:
                            n = 'N/A'
                        obj['Detection'], obj['Modifiers'], obj['Indicator'], obj['IndicatorName'] = \
                            ret['Detection_Type'], ' '.join(ret['Modifiers']), i, n
                        new_row = pd.DataFrame([obj])
                        pdf = pd.concat([pdf.loc[:], new_row]).reset_index(drop=True)
            prot_score = None
            block_lst = []
            try:
                blocks = 0
                tests = 0
                for test in elem['Protections']['Protection_Tests']:
                    for step in test['Substeps']:
                        if rnd == 'carbanak-fin7' or rnd == 'wizard-spider-sandworm':
                            if step['Technique']['Technique_Name'] not in tactic_protections.keys():
                                tactic_protections[step['Technique']['Technique_Name']] = {'Total': 0, 'Blocked': 0}
                        if step['Protection_Type'] != 'N/A':
                            tests += 1
                            tactic_protections[step['Technique']['Technique_Name']]['Total'] += 1
                        if step['Protection_Type'] == 'Blocked':
                            block_lst.append(step['Substep'])
                            tactic_protections[step['Technique']['Technique_Name']]['Blocked'] += 1
                            blocks += 1
                if tests == 0:
                    prot_score = 0
                else:
                    prot_score = blocks/tests
            except KeyError:
                prot_score = 0
            # datasources[rnd][vendor]['Tally'] = tally
            vendor_protections[vendor][rnd] = prot_score
    return pdf, rnd, vendor, block_lst

def score_df(df, rnd):
    tdf = df[df['Modifiers'].str.contains('Correlated|Tainted', na=False)]
    try:
        tainted_telemetry = tdf.Detection.value_counts()['Telemetry']
    except:
        tainted_telemetry = 0
    counts = df.Detection.value_counts()
    try:
        misses = counts['None']
    except KeyError:
        misses = 0
    try:
        MSSP = counts['MSSP']
    except:
        MSSP = 0
    try:
        tactic = counts['Tactic']
    except KeyError:
        tactic = 0
    try:
        general = counts['General']
    except KeyError:
        try:
            general = counts['General Behavior']
        except KeyError:
            general = 0
    try:
        enrich = counts['Enrichment']
    except:
        enrich = 0
    try:
        na = counts['N/A']
    except KeyError:
        na = 0
    substeps = len(df.index) - na
    visibility = (substeps - misses - MSSP)
    quality = 0
    for index, content in df.iterrows():
        if content['Detection'] != 'N/A' or content['Detection'] != 'None' or content['Detection'] != 'MSSP':
            if content['Modifiers'].find('Delayed') == -1 and content['Modifiers'].find('Configuration Change') == -1:
                quality += 1
    cdf = df[df['Modifiers'].str.contains('Delayed|Configuration Change', na=False)]
    # print(cdf['Modifiers'].unique())
    badcounts = cdf.Detection.value_counts()
    try:
        bna = badcounts['N/A']
    except:
        bna = 0
    try:
        bnone = badcounts['None']
    except:
        bnone = 0
    badsteps = len(cdf.index) - bna - bnone
    quality = 1 - (badsteps/int(visibility))
    if type(quality) != float:
        quality = 0
    assert(quality >= 0 and quality <= 1)
    if rnd == 'apt3':
        try:
            techniques = counts['Specific Behavior'] + general + enrich
        except:
            try:
                techniques = counts['General Behavior'] + enrich
            except:
                try:
                    techniques = counts['Enrichment']
                except:
                    techniques = 0
    else:
        try:
            techniques = counts['Technique'] + tactic + general
        except:
            try:
                techniques = counts['Tactic'] + general
            except:
                techniques = general
    analytics = techniques/visibility if visibility != 0 else 0
    if rnd == 'apt3':
        try:
            techniquelevel = counts['Specific Behavior']
        except:
            techniquelevel = 0
        try:
            IOC = counts['Indicator of Compromise']
        except:
            IOC = 0
        try:
            telemetry = counts['Telemetry']
        except:
            telemetry = 0
        # confidence = ((4 * techniquelevel) + (3 * general) + (2 * enrich) + telemetry)/substeps
        detection = techniquelevel + general + enrich + IOC
    else:
        try:
            techniquelevel = counts['Technique']
        except:
            techniquelevel = 0
        try:
            telemetry = counts['Telemetry']
        except:
            telemetry = 0
        # confidence = ((4 * techniquelevel) + (3 * tactic) + (2 * general) + telemetry)/substeps
        detection = techniquelevel + tactic + general
    # visibility /= substeps
    assert detection == visibility-telemetry, f"detection counts ({detection}) should be visibility ({visibility}) minus telemetry counts ({telemetry})"
        
    return visibility, detection, substeps

def query_df(pdf, rnd, mode, query):
    df = pdf[(pdf[mode] == query) & (pdf['Adversary'] == rnd)]
    if len(df.index) == 0:
        return None
    visibility, detection, substeps = score_df(df, rnd)
    # visibility, analytics, quality, confidence = score_df(df, rnd)
    return int(visibility), int(detection), int(substeps)

def analyze_graph(df):
    wizard_spider_list = [
    "1.A.1",
    "1.A.2",
    "1.A.3",
    "1.A.4",
    "1.A.5",
    "1.A.6",
    "1.A.7",
    "1.A.8",
    "1.A.9",
    "1.A.10",
    "1.A.11",
    "2.A.1",
    "3.A.1",
    "3.A.2",
    "3.A.3",
    "3.A.4",
    "3.A.5",
    "4.A.1",
    "4.A.2",
    "4.A.3",
    "4.A.4",
    "4.A.5",
    "5.A.1",
    "5.A.2",
    "5.A.3",
    "5.A.4",
    "5.A.5",
    "5.A.6",
    "5.A.7",
    "5.A.8",
    "5.A.9",
    "6.A.1",
    "6.A.2",
    "7.A.1",
    "7.A.2",
    "7.A.3",
    "7.A.4",
    "7.A.5",
    "8.A.1",
    "8.A.2",
    "9.A.1",
    "9.A.2",
    "9.A.3",
    "9.A.4",
    "9.A.5",
    "10.A.1",
    "10.A.2",
    "10.A.3",
    "10.A.4",
    "10.A.5",
    "10.A.6",
    "10.A.7"]

    sandworm_list = ['11.A.1', '11.A.2', '11.A.3', '11.A.4', '12.A.1', '12.A.2', '12.A.3', '12.A.4', '12.A.5', '13.A.1', '13.A.2', '13.A.3', '13.A.4', '13.A.5', '14.A.1', '14.A.2', '14.A.3', '14.A.4', '14.A.5', '15.A.1', '15.A.2', '15.A.3', '15.A.4', '15.A.5', '15.A.6', '15.A.7', '15.A.8', '15.A.9', '15.A.10', '16.A.1', '16.A.2', '16.A.3', '16.A.4', '16.A.5', '17.A.1', '17.A.2', '17.A.3', '17.A.4', '17.A.5', '17.A.6', '17.A.7', '17.A.8', '18.A.1', '18.A.2', '18.A.3', '18.A.4', '19.A.1', '19.A.2', '19.A.3', '19.A.4', '19.A.5', '19.A.6', '19.A.7', '19.A.8', '19.A.9', '19.A.10', '19.A.11']


    wizard_spider_connectivity = {
    0: [1, 2],
    1: [0],
    2: [0, 3],
    3: [2, 5, 6],
    4: [],
    5: [3],
    6: [3, 7],
    7: [6, 8],
    8: [7, 9, 11, 12, 13, 14, 15, 16],
    9: [8],
    10: [],
    11: [8],
    12: [8],
    13: [8],
    14: [8],
    15: [8],
    16: [8],
    17: [19, 20],
    18: [],
    19: [17, 20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31],
    20: [17, 19],
    21: [],
    22: [19],
    23: [19],
    24: [19],
    25: [19],
    26: [19],
    27: [19],
    28: [19],
    29: [19],
    30: [19],
    31: [19, 32],
    32: [31],
    33: [35, 36, 37, 38, 39],
    34: [],
    35: [33],
    36: [33],
    37: [33],
    38: [33, 40, 41, 42, 43, 44, 45],
    39: [33],
    40: [38],
    41: [38],
    42: [38],
    43: [38],
    44: [38],
    45: [38, 46, 47, 48, 49, 50, 51],
    46: [45],
    47: [45],
    48: [45],
    49: [45],
    50: [45],
    51: [45]}

    sandworm_connectivity = {
    0: [2],
    1: [],
    2: [0, 3],
    3: [2, 4],
    4: [3, 5, 6, 7, 8],
    5: [4],
    6: [4],
    7: [4],
    8: [4],
    9: [4, 10],
    10: [9, 11, 14, 15, 16, 17, 18],
    11: [10],
    12: [],
    13: [],
    14: [10],
    15: [10],
    16: [10],
    17: [10],
    18: [10],
    19: [21, 22],
    20: [],
    21: [19, 26],
    22: [19, 23],
    23: [22, 24],
    24: [23, 25, 26],
    25: [24],
    26: [21, 24, 27, 29, 30, 31, 32, 34, 36, 38, 39, 40, 41],
    27: [26],
    28: [],
    29: [26],
    30: [26],
    31: [26],
    32: [26, 33],
    33: [32],
    34: [26, 35, 41],
    35: [34],
    36: [26, 37, 41],
    37: [36],
    38: [26, 39, 41],
    39: [26, 38],
    40: [26],
    41: [26, 34, 36, 38],
    42: [44],
    43: [],
    44: [42, 45],
    45: [44, 46],
    46: [45, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56],
    47: [46],
    48: [46],
    49: [46],
    50: [46],
    51: [46],
    52: [46],
    53: [46],
    54: [46],
    55: [46],
    56: [46]}

    exist = {}
    above_tel = {}
    miss = []
    wizard_spider_skip = [4, 10, 18, 21, 34]
    sandworm_skip = [1, 12, 13, 20, 28, 43]
    not_supported = []

    for index, row in df.iterrows():
        detection = row["Detection"]
        substep = row["Substep"]
        # try:
        #     idx = wizard_spider_list.index(substep)
        # 
        #     idx = sandworm_list.index()
        if substep in wizard_spider_list:
            idx = wizard_spider_list.index(substep)
        elif substep in sandworm_list:
            idx = sandworm_list.index(substep) + 52
        # print(idx)

        if (idx in wizard_spider_skip) or (idx-52 in sandworm_skip):
            # print("skipping...")
            continue
        if detection == 'N/A':
            not_supported.append(substep)
        elif detection != 'None':
            if idx < 52:
                # print("idx in wizard_spider")
                exist[idx] = wizard_spider_connectivity[idx]
                if detection != 'Telemetry':
                    above_tel[idx] = wizard_spider_connectivity[idx]
            else:
                # print("idx in sandworm")
                exist[idx] = sandworm_connectivity[idx-52]
                if detection != 'Telemetry':
                    above_tel[idx] = sandworm_connectivity[idx-52]
        else:
            miss.append(idx)
        # print(idx)
    g = Graph()
    for v in exist:
        g.add_node(v)
        # print('adding node: ', v)
    for v in exist:
        for w in exist[v]:
            if v < 52:
                tmp_w = w
            else:
                tmp_w = w + 52
            if tmp_w in exist:
                g.add_edge(v,tmp_w)
            # print('adding edge to: ', tmp_w)
    cc = g.connected_components()
    # print("Following are connected components")
    # print(cc)
    # print(len(cc))
    # print(miss)
    # print(connection)
    # print(len(connection))
    return cc, exist, above_tel, not_supported


def run_analysis(filenames):
    tdf = pd.DataFrame(columns=('Vendor', 'Adversary', 'Substep', 'Criteria', 'Tactic', 'TechniqueId', 'TechniqueName', 'SubtechniqueId', 'Detection', 'Modifiers'))
    if not os.path.exists(os.path.join(os.getcwd(), 'results/vendor_results.json')):
        vendor_results = {}
        seg_dict = {}
        block_dict = {}
        not_supported_dict = {}
        for file in filenames:
            try:
                df, adversary, vendor, block_lst = crawl_results(file)
                if adversary == 'wizard-spider-sandworm':
                    segmentation, visibility, detection, not_supported = analyze_graph(df)
                    seg_dict[vendor] = {'seg':segmentation, 'vis': visibility, 'det': detection}
                    block_dict[vendor] = block_lst
                    not_supported_dict[vendor] = not_supported
                if adversary not in vendor_results.keys():
                    vendor_results[adversary] = {}
                tdf = pd.concat([tdf.loc[:], df]).reset_index(drop=True)
                # tdf = tdf.append(df, ignore_index=True)
                visibility, detection, substeps = query_df(df, adversary, 'Vendor', vendor)
                # g = None
                # g_v = None
                # g_q = None
                # g_c = None
                # pct = analytics * 100
                # pct_v = visibility * 100
                # pct_q = quality * 100
                # pct_c = confidence * 100
                # for grade in grading.keys():
                #     low = grading[grade][0]
                #     high = grading[grade][1]
                #     if pct >= low and pct <= high:
                #         g = grade
                #     if pct_v >= low and pct_v <= high:
                #         g_v = grade
                #     if pct_q >= low and pct_q <= high:
                #         g_q = grade
                #     if pct_c >= low and pct_c <= high:
                #         g_c = grade
                # if adversary == 'carbanak-fin7' or adversary == 'wizard-spider-sandworm':
                #     tally = datasources[adversary][vendor]['Tally']
                #     availability = (sum(datasources[adversary][vendor].values()) - tally)/tally
                #     vendor_results[adversary][vendor] = {'Visibility': visibility, 'Analytics': analytics, 'Quality': quality, 'Confidence': confidence, 'Protection': vendor_protections[vendor][adversary], 'Availability': availability}
                # else:
                vendor_results[adversary][vendor] = {'Visibility': visibility, 'Detection': detection, 'Substeps': substeps}
            except Exception as e:
                print(e)
        
        # max_ = 0
        # for vendor in vendor_results['carbanak-fin7'].keys():
        #     if vendor_results['carbanak-fin7'][vendor]['Availability'] > max_:
        #         max_ = vendor_results['carbanak-fin7'][vendor]['Availability']
        # for vendor in vendor_results['carbanak-fin7'].keys():
        #     vendor_results['carbanak-fin7'][vendor]['Availability'] /= max_
        with open('results/vendor_results.json', 'w') as fp:
            json.dump(vendor_results, fp, indent=4)
        # print(seg_dict)
        # print(block_dict)
        # print(not_supported_dict)
    else:
        with open('results/vendor_results.json', 'r') as fp:
            vendor_results = json.load(fp)
    if not os.path.exists(os.path.join(os.getcwd(), 'results/tactic_results.json')):
        tactic_results = {}
        for adversary in evaluations:
            tactic_results[adversary] = {}
            for tactic in technique_coverage[adversary].keys():
                tactic_results[adversary][tactic] = {}
                for technique in technique_coverage[adversary][tactic]:
                    vis = 0
                    ana = 0
                    qua = 0
                    conf = 0
                    tally = 0
                    try:
                        #for vendor in participants_by_eval[adversary]:
                        #df = crawl_results(vendor + '_Results.json', adversary)
                        visibility, detection, substeps = query_df(tdf, adversary, 'TechniqueName', technique)
                        # try:
                        #     prot = tactic_protections[technique]['Blocked']/tactic_protections[technique]['Total']
                        # except:
                        #     prot = 0
                        tactic_results[adversary][tactic][technique] = {'Visibility': visibility, 'Detection': detection, 'Substeps': substeps}
                    except Exception as e:
                        pass
        with open('results/tactic_results.json', 'w') as fp:
            json.dump(tactic_results, fp, indent=4)
    else:
        with open('results/tactic_results.json', 'r') as fp:
            tactic_results = json.load(fp)
    
    return vendor_results, tactic_results, vendor_protections

def graph_results(adversary, vendor_results, tactic_results=None):
    sns.set_theme(color_codes=True)
    colors = {
        'Visibility': 'green',
        'Analytics': 'red',
        'Quality': 'blue'
    }
    vendors = participants_by_eval[adversary]
    visibility = []
    analytics = []
    for vendor in vendors:
        item = vendor_results[adversary][vendor]
        visibility.append(item['Visibility'])
        analytics.append(item['Analytics'])
    fig = plt.figure(figsize=(12, 12))
    vendors, visibility, analytics = [list(t) for t in zip(*sorted(zip(vendors, visibility, analytics), key=lambda x: x[1] + x[2]))]
    points = list(zip(visibility, analytics))
    df = pd.DataFrame(points, columns=['Visibility', 'Analytics'], index=vendors)
    g = sns.scatterplot(x='Visibility', y='Analytics', data=df)
    g.tick_params(labelsize=14)
    g.set_xlabel("Visibility", fontsize = 20)
    g.set_ylabel("Analytics", fontsize = 20)
    for line in range(0,df.shape[0]):
        if adversary == 'carbanak-fin7':
            if df.index[line] == 'Bitdefender':
                g.text(df['Visibility'][line]+0.005, df['Analytics'][line]+ 0.015, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'CheckPoint':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line] - 0.005, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Microsoft':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line] - 0.005, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Sophos':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line] + 0.015, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Cisco':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line] - 0.015, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            else:
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line], 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
        elif adversary == 'apt29':
            if df.index[line] == 'VMware':
                g.text(df['Visibility'][line]+0.007 , df['Analytics'][line]+ 0.02, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'TrendMicro':
                g.text(df['Visibility'][line]+0.01 , df['Analytics'][line]-0.005, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Symantec':
                g.text(df['Visibility'][line]+0.01 , df['Analytics'][line]+0.007, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'PaloAltoNetworks':
                g.text(df['Visibility'][line]+0.01 , df['Analytics'][line]-0.005, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'CrowdStrike':
                g.text(df['Visibility'][line]+0.01 , df['Analytics'][line]+0.01, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Microsoft':
                g.text(df['Visibility'][line]+0.01 , df['Analytics'][line]-0.005, 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
            else:
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line], 
                df.index[line], horizontalalignment='left', 
                    size=14, color='black', weight='semibold', rotation=30)
        elif adversary == 'apt3':
            if df.index[line] == 'F-Secure':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line]-0.01, 
                    df.index[line], horizontalalignment='left', 
                    size=20, color='black', weight='semibold', rotation=30)
            elif df.index[line] == 'Cybereason':
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line]+0.01, 
                    df.index[line], horizontalalignment='left', 
                    size=20, color='black', weight='semibold', rotation=30)
            else:
                g.text(df['Visibility'][line]+0.01, df['Analytics'][line], 
                    df.index[line], horizontalalignment='left', 
                    size=20, color='black', weight='semibold', rotation=30)
    plt.xlim(0, 1)
    plt.ylim(0, 1)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/graphs/{adversary}/Vendor Breakdown.png')
    plt.close()

    quality = []
    for vendor in vendors:
        quality.append(vendor_results[adversary][vendor]['Quality'])
    fig = plt.figure(figsize=(12, 12))
    quality, vendors = [list(t) for t in zip(*sorted(zip(quality, vendors), key=lambda x: x[0]))]
    indices = range(len(vendors))
    points = list(zip(indices, quality))
    df = pd.DataFrame(points, columns=['Vendor', 'Quality'], index=vendors)
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Quality', data=df, palette=("Reds_d"))
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 20)
    g.set_ylabel("Quality", fontsize = 20)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    g.set_yticklabels([x/5 for x in list(range(6))], fontsize = 18)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/graphs/{adversary}/Quality Breakdown.png')
    plt.close()

    confidence = []
    analytics = []
    for vendor in vendors:
        confidence.append(vendor_results[adversary][vendor]['Confidence'])
    fig = plt.figure(figsize=(12, 12))
    confidence, vendors = [list(t) for t in zip(*sorted(zip(confidence, vendors), key=lambda x: x[0]))]
    indices = range(len(vendors))
    points = list(zip(vendors, confidence))
    df = pd.DataFrame(points, columns=['Vendor', 'Confidence'], index=indices)
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Confidence', data=df, palette=("Blues_d"))
    g.tick_params(labelsize=10)
    plt.autoscale(False)
    g.set_xlabel("Vendor", fontsize = 20)
    g.set_ylabel("Confidence", fontsize = 20)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    g.set_yticks(list(range(5)))
    plt.ylim(0, 4)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/graphs/{adversary}/Confidence Breakdown.png')
    plt.close()

def graph_protections(adversary):
    import matplotlib.ticker as ticker
    protections = []
    vendors = []
    with open('results/vendor_results.json', 'r') as fp:
        vendor_results = json.load(fp)
    for vendor in vendor_results[adversary].keys():
        vendors.append(vendor)
        if vendor_results[adversary][vendor]['Protection'] != 'N/A':
            protections.append(vendor_results[adversary][vendor]['Protection'])
        else:
            protections.append(float(0))
    fig = plt.figure(figsize=(12, 12))
    indices = range(len(vendors))
    protections, vendors = [list(t) for t in zip(*sorted(zip(protections, vendors), key=lambda x: x[0]))]
    points = list(zip(indices, protections))
    df = pd.DataFrame(points, columns=['Vendor', 'Protection'])
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Protection', data=df, palette=("Greens_d"))
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Protection", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 16)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/graphs/{adversary}/Protection Breakdown.png')
    plt.close()

def graph_rankings(rnd):
    import matplotlib.ticker as ticker
    scores = []
    vendors = []
    with open(f'results/{rnd}_vendor_Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        for row in reader:
            if row[1] == 'Unweighted Score':
                continue
            scores.append(float(row[1]))
            vendors.append(row[0])

    fig = plt.figure(figsize=(12, 12))
    indices = range(len(vendors))
    points = list(zip(reversed(indices), reversed(scores)))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette='YlGn_r')
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Unweighted Score", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/graphs/{rnd}/Unweighted_Vendor_Rankings.png')
    plt.close()

    scores = []
    vendors = []
    with open(f'results/{rnd}_vendor_Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        for row in reader:
            if row[1] == 'Unweighted Score':
                continue
            scores.append(float(row[2]))
            vendors.append(row[0])

    fig = plt.figure(figsize=(12, 12))
    indices = range(len(vendors))
    scores, vendors = [list(t) for t in zip(*sorted(zip(scores, vendors), key=lambda x: x[0]))]
    points = list(zip(indices, scores))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette='YlGn_r')
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Weighted Score", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/graphs/{rnd}/Weighted_Vendor_Rankings(Detection).png')
    plt.close()

    scores = []
    vendors = []
    with open(f'results/{rnd}_vendor_Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        for row in reader:
            if row[1] == 'Unweighted Score':
                continue
            scores.append(float(row[3]))
            vendors.append(row[0])

    fig = plt.figure(figsize=(12, 12))
    scores, vendors = [list(t) for t in zip(*sorted(zip(scores, vendors), key=lambda x: x[0]))]
    indices = range(len(vendors))
    points = list(zip(indices, scores))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette='YlGn_r')
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Weighted Score", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/graphs/{rnd}/Weighted_Vendor_Rankings(Correlation).png')
    plt.close()

    scores = []
    vendors = []
    with open(f'results/{rnd}_vendor_Rankings.csv', 'r') as fp:
        reader = csv.reader(fp)
        for row in reader:
            if row[1] == 'Unweighted Score':
                continue
            scores.append(float(row[4]))
            vendors.append(row[0])

    fig = plt.figure(figsize=(12, 12))
    indices = range(len(vendors))
    scores, vendors = [list(t) for t in zip(*sorted(zip(scores, vendors), key=lambda x: x[0]))]
    points = list(zip(indices, scores))
    df = pd.DataFrame(points, columns=['Vendor', 'Grade'])
    sns.set(rc={'axes.facecolor': '#e8e8e8'})
    g = sns.barplot(x='Vendor', y='Grade', data=df, palette='YlGn_r')
    g.yaxis.set_major_locator(ticker.MultipleLocator(0.05))
    g.yaxis.set_major_formatter(ticker.ScalarFormatter())
    g.tick_params(labelsize=10)
    g.set_xlabel("Vendor", fontsize = 16)
    g.set_ylabel("Weighted Score", fontsize = 16)
    g.set_xticklabels(vendors, rotation=90, fontsize = 12)
    plt.gca().invert_xaxis()
    plt.ylim(0, 1)
    plt.autoscale(False)
    plt.tight_layout()
    plt.savefig(os.getcwd() + f'/graphs/{rnd}/Weighted_Vendor_Rankings(Automation).png')
    plt.close()

def make_vendor_ranking(vendor_results, rnd, weighted=True):
    rankings = {}
    if weighted is True:
        for vendor in vendor_results[rnd].keys():
            rankings[vendor] = {}
            if rnd == 'carbanak-fin7' or rnd == 'wizard-spider-sandworm':
                prot = 0 if vendor_results[rnd][vendor]['Protection'] == 'N/A' else vendor_results[rnd][vendor]['Protection']
                weighted_score = (.25 * prot) + (.25 * vendor_results[rnd][vendor]['Visibility']) + (.2 * vendor_results[rnd][vendor]['Analytics']) + (.2 * (vendor_results[rnd][vendor]['Confidence']/4)) + (.1 * vendor_results[rnd][vendor]['Quality'])
                unweighted_score = vendor_results[rnd][vendor]['Visibility'] + vendor_results[rnd][vendor]['Analytics'] + (vendor_results[rnd][vendor]['Confidence']/4) + vendor_results[rnd][vendor]['Quality']
                unweighted_score /= 4
                rankings[vendor]['Weighted'] = weighted_score
                rankings[vendor]['Unweighted'] = unweighted_score
            else:
                weighted_score = (.3 * vendor_results[rnd][vendor]['Visibility']) + (.25 * vendor_results[rnd][vendor]['Analytics']) + (.25 * (vendor_results[rnd][vendor]['Confidence']/4)) + (.2 * vendor_results[rnd][vendor]['Quality'])
                unweighted_score = vendor_results[rnd][vendor]['Visibility'] + vendor_results[rnd][vendor]['Analytics'] + (vendor_results[rnd][vendor]['Confidence']/4) + vendor_results[rnd][vendor]['Quality']
                unweighted_score /= 4
                rankings[vendor]['Weighted'] = weighted_score
                rankings[vendor]['Unweighted'] = unweighted_score
    return rankings

def make_technique_ranking(tactic_results, rnd, weighted=True):
    rankings = {}
    if weighted is True:
        for tactic in tactic_results[rnd].keys():
            rankings[tactic] = {}
            for technique in tactic_results[rnd][tactic].keys():
                rankings[tactic][technique] = {}
                if rnd == 'carbanak-fin7' or rnd == 'wizard-spider-sandworm':
                    prot = 0 if tactic_results[rnd][tactic][technique]['Protection'] == 'N/A' else tactic_results[rnd][tactic][technique]['Protection']
                    weighted_score = (.25 * prot) + (.25 * tactic_results[rnd][tactic][technique]['Visibility']) + (.2 * tactic_results[rnd][tactic][technique]['Analytics']) + (.2 * (tactic_results[rnd][tactic][technique]['Confidence']/4)) + (.1 * tactic_results[rnd][tactic][technique]['Quality'])
                    unweighted_score = tactic_results[rnd][tactic][technique]['Visibility'] + tactic_results[rnd][tactic][technique]['Analytics'] + (tactic_results[rnd][tactic][technique]['Confidence']/4) + tactic_results[rnd][tactic][technique]['Quality']
                    unweighted_score /= 4
                    rankings[tactic][technique]['Weighted'] = weighted_score
                    rankings[tactic][technique]['Unweighted'] = unweighted_score
                else:
                    weighted_score = (.3 * tactic_results[rnd][tactic][technique]['Visibility']) + (.25 * tactic_results[rnd][tactic][technique]['Analytics']) + (.25 * (tactic_results[rnd][tactic][technique]['Confidence']/4)) + (.2 * tactic_results[rnd][tactic][technique]['Quality'])
                    unweighted_score = tactic_results[rnd][tactic][technique]['Visibility'] + tactic_results[rnd][tactic][technique]['Analytics'] + (tactic_results[rnd][tactic][technique]['Confidence']/4) + tactic_results[rnd][tactic][technique]['Quality']
                    unweighted_score /= 4
                    rankings[tactic][technique]['Weighted'] = weighted_score
                    rankings[tactic][technique]['Unweighted'] = unweighted_score
    return rankings

def make_tactic_rankings(tactic_results, rnd):
    technique_ranks = {}
    tactic_ranks = {}
    for category in tactic_results[rnd].keys():
        technique_ranks[category] = {}
        li = []
        for technique in tactic_results[rnd][category].keys():
            score = (.3 * tactic_results[rnd][category][technique]['Visibility']) + (.25 * tactic_results[rnd][category][technique]['Analytics']) + (.25 * (tactic_results[rnd][category][technique]['Confidence']/4)) + (.2 * tactic_results[rnd][category][technique]['Quality'])
            technique_ranks[category][technique] = score
            li.append(score)
        tactic_ranks[category] = sum(li)/len(li)

    return technique_ranks, tactic_ranks

def make_3d_plot(vendor_results):
    from mpl_toolkits.mplot3d import Axes3D
    detection_scores = []
    correlation_scores = []
    automation_scores = []
    vendors = []
    for vendor in vendor_results['carbanak-fin7'].keys():
        vendors.append(vendor)
        detection_scores.append(vendor_results['carbanak-fin7'][vendor]['Visibility'])
        correlation_scores.append((vendor_results['carbanak-fin7'][vendor]['Analytics'] + (vendor_results['carbanak-fin7'][vendor]['Confidence']/4))/2)
        automation_scores.append((vendor_results['carbanak-fin7'][vendor]['Quality'] + vendor_results['carbanak-fin7'][vendor]['Protection'])/2)

    fig = plt.figure()
    ax = fig.add_subplot(111, projection='3d')

    ax.scatter(detection_scores, correlation_scores, automation_scores, c='r', marker='o')
    ax.set_xlabel('Detection Ability')
    ax.set_ylabel('Correlation Ability')
    ax.set_zlabel('Automation Ability')

    plt.show()

def run_eval():
    vendor_results, tactic_results, vendor_protections = run_analysis(filenames)
    rankings = {}
    for adversary in vendor_results.keys():
        # ranking = make_vendor_ranking(vendor_results, adversary)
        # rankings[adversary] = ranking
        with open(f'results/{adversary}_vendor_Rankings.csv', 'w', newline='') as fp:
            writer = csv.writer(fp)
            writer.writerow(['Vendor', 'Visibility', 'Detection', 'Substeps'])
            for vendor, vendor_dict in vendor_results[adversary].items():
                try:
                    writer.writerow([vendor, "%.3f" % vendor_dict['Visibility'], "%.3f" %  vendor_dict['Detection'], "%.3f" %  vendor_dict['Substeps']])
                except Exception as e:
                    print(e)
            # if adversary == 'carbanak-fin7' or adversary == 'wizard-spider-sandworm':
            #     writer.writerow(['Vendor', 'Unweighted Score', 'Detection Priority Score', 'Correlation Priority Score', 'Automation Priority Score', 'Visibility', 'Analytics', 'Confidence', 'Quality', 'Protection'])
            #     rs = []
            #     vs = []
            #     us = []
            #     for vendor in ranking.keys():
            #         vs.append(vendor)
            #         rs.append(ranking[vendor]['Unweighted'])
            #     vs, rs = [list(t) for t in zip(*sorted(zip(vs, rs), key=lambda x: x[1]))]
            #     scores = zip(reversed(vs), reversed(rs))
            #     for item in scores:
            #         if vendor_results[adversary][item[0]]['Protection'] == 'N/A':
            #             prot = 0
            #         else:
            #             prot = vendor_results[adversary][item[0]]['Protection']
            #         visibility = vendor_results[adversary][item[0]]['Visibility']
            #         analytics = vendor_results[adversary][item[0]]['Analytics']
            #         confidence = vendor_results[adversary][item[0]]['Confidence']/4
            #         quality = vendor_results[adversary][item[0]]['Quality']
            #         det_score = (.3 * visibility)+ (.175 * analytics) + (.175 * confidence) + (.175 * quality) + (.175 * prot)
            #         corr_score = (.2 * visibility)+ (.25 * analytics) + (.25 * confidence) + (.20 * quality) + (.10 * prot)
            #         auto_score = (.2 * visibility)+ (.15 * analytics) + (.15 * confidence) + (.25 * quality) + (.25 * prot)
            #         try:
            #             writer.writerow([item[0], "%.3f" % item[1], "%.3f" % det_score, "%.3f" % corr_score, "%.3f" % auto_score, "%.3f" % vendor_results[adversary][item[0]]['Visibility'], "%.3f" % vendor_results[adversary][item[0]]['Analytics'],"%.3f" % (vendor_results[adversary][item[0]]['Confidence']/4), "%.3f" % vendor_results[adversary][item[0]]['Quality'], "%.3f" % prot])
                    # except Exception as e:
                    #     print(e)
            # else:
            #     writer.writerow(['Vendor', 'Unweighted Score', 'Visibility', 'Analytics', 'Confidence', 'Quality'])
            #     rs = []
            #     vs = []
            #     for vendor in ranking.keys():
            #         vs.append(vendor)
            #         rs.append(ranking[vendor]['Unweighted'])
            #     vs, rs = [list(t) for t in zip(*sorted(zip(vs, rs), key=lambda x: x[1]))]
            #     scores = zip(reversed(vs), reversed(rs))
            #     for item in scores:
            #         try:
            #             writer.writerow([item[0], "%.3f" % item[1], "%.3f" %  vendor_results[adversary][item[0]]['Visibility'], "%.3f" %  vendor_results[adversary][item[0]]['Analytics'],"%.3f" %  (vendor_results[adversary][item[0]]['Confidence']/4), "%.3f" %  vendor_results[adversary][item[0]]['Quality']])
            #         except:
            #             pass
    
    for adversary in tactic_results.keys():
        # ranking = make_technique_ranking(tactic_results, adversary)
        # rankings[adversary] = ranking
        with open(f'results/{adversary}_technique_Rankings.csv', 'w', newline='') as fp:
            writer = csv.writer(fp)
            writer.writerow(['Tactic', 'Technique', 'Visibility', 'Detection', 'Substeps'])
            for tactic in tactic_results[adversary].keys():
                for technique, technique_dict in tactic_results[adversary][tactic].items():
                    try:
                        writer.writerow([tactic, technique, "%.3f" % technique_dict['Visibility'], "%.3f" %  technique_dict['Detection'], "%.3f" %  technique_dict['Substeps']])
                    except Exception as e:
                        print(e)
            # if adversary == 'carbanak-fin7' or adversary == 'wizard-spider-sandworm':
            #     writer.writerow(['Tactic', 'Technique', 'Unweighted Score', 'Detection Priority Score', 'Correlation Priority Score', 'Automation Priority Score', 'Visibility', 'Analytics', 'Confidence', 'Quality', 'Protection'])
            #     rs = []
            #     ts = []
            #     us = []
            #     for tactic in ranking.keys():
            #         for technique in ranking[tactic].keys():
            #             us.append(tactic)
            #             ts.append(technique)
            #             rs.append(ranking[tactic][technique]['Unweighted'])
            #     us, ts, rs = [list(t) for t in zip(*sorted(zip(us, ts, rs), key=lambda x: x[2]))]
            #     scores = zip(reversed(us), reversed(ts), reversed(rs))
            #     for item in scores:
            #         if tactic_results[adversary][item[0]][item[1]]['Protection'] == 'N/A':
            #             prot = 0
            #         else:
            #             prot = tactic_results[adversary][item[0]][item[1]]['Protection']
            #         visibility = tactic_results[adversary][item[0]][item[1]]['Visibility']
            #         analytics = tactic_results[adversary][item[0]][item[1]]['Analytics']
            #         confidence = tactic_results[adversary][item[0]][item[1]]['Confidence']/4
            #         quality = tactic_results[adversary][item[0]][item[1]]['Quality']
            #         det_score = (.3 * visibility)+ (.175 * analytics) + (.175 * confidence) + (.175 * quality) + (.175 * prot)
            #         corr_score = (.2 * visibility)+ (.25 * analytics) + (.25 * confidence) + (.20 * quality) + (.10 * prot)
            #         auto_score = (.2 * visibility)+ (.15 * analytics) + (.15 * confidence) + (.25 * quality) + (.25 * prot)
            #         try:
            #             writer.writerow([item[0], item[1], "%.3f" % item[2], "%.3f" % det_score, "%.3f" % corr_score, "%.3f" % auto_score, "%.3f" % tactic_results[adversary][item[0]][item[1]]['Visibility'], "%.3f" % tactic_results[adversary][item[0]][item[1]]['Analytics'],"%.3f" % (tactic_results[adversary][item[0]][item[1]]['Confidence']/4), "%.3f" % tactic_results[adversary][item[0]][item[1]]['Quality'], "%.3f" % prot])
            #         except Exception as e:
            #             print(e)
            # else:
            #     writer.writerow(['Tactic', 'Technique', 'Unweighted Score', 'Visibility', 'Analytics', 'Confidence', 'Quality'])
            #     rs = []
            #     ts = []
            #     us = []
            #     for tactic in ranking.keys():
            #         for technique in ranking[tactic].keys():
            #             us.append(tactic)
            #             ts.append(technique)
            #             rs.append(ranking[tactic][technique]['Unweighted'])
            #     us, ts, rs = [list(t) for t in zip(*sorted(zip(us, ts, rs), key=lambda x: x[2]))]
            #     scores = zip(reversed(us), reversed(ts), reversed(rs))
            #     for item in scores:
            #         try:
            #             writer.writerow([item[0], item[1], "%.3f" % item[2], "%.3f" %  tactic_results[adversary][item[0]][item[1]]['Visibility'], "%.3f" %  tactic_results[adversary][item[0]][item[1]]['Analytics'],"%.3f" %  (tactic_results[adversary][item[0]][item[1]]['Confidence']/4), "%.3f" %  tactic_results[adversary][item[0]][item[1]]['Quality']])
            #         except:
            #             pass
    technique_set_1 = set()
    for tactic in technique_coverage['carbanak-fin7'].keys():
        for t in technique_coverage['carbanak-fin7'][tactic]:
            technique_set_1.add(t)
            # print(f'adding {t} to the set, size: {len(technique_set_1)}')
    print(f'there are {len(technique_set_1)} techniques in carbanak-fin7')
    technique_set_2 = set()
    for tactic in technique_coverage['wizard-spider-sandworm'].keys():
        for t in technique_coverage['wizard-spider-sandworm'][tactic]:
            technique_set_2.add(t)
            # print(f'adding {t} to the set, size: {len(technique_set_2)}')
    print(f'there are {len(technique_set_2)} techniques in wizard-spider-sandworm')
    technique_set_3 = set()
    for tactic in technique_coverage['apt3'].keys():
        for t in technique_coverage['apt3'][tactic]:
            technique_set_3.add(t)
            # print(f'adding {t} to the set, size: {len(technique_set_2)}')
    print(f'there are {len(technique_set_3)} techniques in apt3')
    technique_set_4 = set()
    for tactic in technique_coverage['apt29'].keys():
        for t in technique_coverage['apt29'][tactic]:
            technique_set_4.add(t)
            # print(f'adding {t} to the set, size: {len(technique_set_2)}')
    print(f'there are {len(technique_set_4)} techniques in apt29')

    technique_set = technique_set_1 | technique_set_2
    print(f'there are {len(technique_set)} techniques in two evluations')

    total_technique_set = technique_set_1 | technique_set_2 | technique_set_3 | technique_set_4
    print(f'there are {len(total_technique_set)} techniques in four evluations')

    vendor_lst = []
    for adv in vendor_results:
        for vendor in vendor_results[adv]:
            if vendor not in vendor_lst:
                vendor_lst.append(vendor)
    print(f'there are {len(vendor_lst)} vendors participated in evaluations')

    # graph_rankings('carbanak-fin7')
    # graph_rankings('wizard-spider-sandworm')
    # graph_results('carbanak-fin7', vendor_results, tactic_results)
    # graph_protections('carbanak-fin7')
    # graph_protections('wizard-spider-sandworm')
    

if __name__ == "__main__":
    run_eval()