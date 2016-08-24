#!/usr/bin/python

import sys
import operator
import json
import argparse

def parse_log (logfile,analyze_domain,analyze_specifics):
    quarantine_cnt = 0
    reject_cnt = 0

    none_policy = dict()
    reject_policy = dict()
    quarantine_policy = dict()

    none_dict = dict()
    quarantine_dict = dict()
    reject_dict = dict()

    percent_dict = dict()

    with open(logfile) as f:
        content = f.readlines()

    for line in content:
        fields = line.strip().split("@")
        if len(fields) >= 12:
            domain = fields[3].strip()
            requested_policy = fields[9].strip()
            percent = fields[10].strip()
            policy = fields[11].strip()

            include_in_analysis = False
            if not analyze_domain and not analyze_specifics:
                include_in_analysis = True
            elif analyze_domain and analyze_specifics and domain == analyze_domain and fields[int(analyze_specifics[0])] == analyze_specifics[1]:
                include_in_analysis = True
            elif not analyze_specifics and analyze_domain and domain == analyze_domain:
                include_in_analysis = True
            elif not analyze_domain and analyze_specifics and fields[int(analyze_specifics[0])] == analyze_specifics[1]:
                include_in_analysis = True

            if include_in_analysis:
                try:
                    percent_dict[domain] = float(percent) / 100.0
                except:
                    pass

            if requested_policy == "none" and include_in_analysis:
                in_none = domain in none_policy
                count = none_policy[domain] if in_none else 0
                none_policy[domain] = count + 1

                if policy == "none":
                    in_none = domain in none_dict
                    count = none_dict[domain] if in_none else 0
                    none_dict[domain] = count + 1
            elif requested_policy == "quarantine" and include_in_analysis:
                in_quar = domain in quarantine_policy
                count = quarantine_policy[domain] if in_quar else 0
                quarantine_policy[domain] = count + 1

                if policy == "quarantine":
                    in_quar = domain in quarantine_dict
                    count = quarantine_dict[domain] if in_quar else 0
                    quarantine_dict[domain] = count + 1
            elif requested_policy == "reject" and include_in_analysis:
                in_reject = domain in reject_policy
                count = reject_policy[domain] if in_reject else 0
                reject_policy[domain] = count + 1

                if policy == "reject":
                    in_reject = domain in reject_dict
                    count = reject_dict[domain] if in_reject else 0
                    reject_dict[domain] = count + 1

    for domain,percent in percent_dict.iteritems():
        try:
            reject_dict[domain] = reject_dict[domain] * percent
            if percent != 1.0:
                quarantine_dict[domain] = reject_dict[domain] * (1-percent)
        except:
            pass

    for domain,count in quarantine_dict.iteritems():
        quarantine_cnt = quarantine_cnt + count

    for domain,count in reject_dict.iteritems():
        reject_cnt = reject_cnt + count

    sorted_reject = sorted(reject_dict.items(), key=operator.itemgetter(1), reverse=True)
    sorted_quarantine = sorted(quarantine_dict.items(), key=operator.itemgetter(1), reverse=True)
    sorted_none = sorted(none_dict.items(), key=operator.itemgetter(1), reverse=True)

    report = dict()

    report['filename'] = logfile

    total_domains = len(none_policy) + len(quarantine_policy) + len(reject_policy)
    report['total_domains'] = total_domains

    report['domains_none'] = len(none_policy)
    report['domains_quarantine'] = len(quarantine_policy)
    report['domains_reject'] = len(reject_policy)

    report['msgs_quarantined'] = int(quarantine_cnt)
    report['msgs_rejected'] = int(reject_cnt)

    domains_rejected = dict()
    cnt = 0
    for reject in sorted_reject:
        if cnt >= 20:
            break
        domains_rejected[reject[0]] = int(reject[1])
        cnt = cnt + 1

    domains_quarantined = dict()
    cnt = 0
    for quarantine in sorted_quarantine:
        if cnt >= 20:
            break
        domains_quarantined[quarantine[0]] = quarantine[1]
        cnt = cnt + 1

    domains_none = dict()
    cnt = 0
    for none in sorted_none:
        if cnt >= 20:
            break
        domains_none[none[0]] = none[1]
        cnt = cnt + 1

    report['domains_quarantined'] = domains_quarantined
    report['domains_rejected'] = domains_rejected
    report['domains_noned'] = domains_none

    return json.dumps(report)

def generate_report(report_json):
    json_dict = json.loads(report_json)

    report_str = "\n\n---------------------------------------------------------------\n\n"
    report_str = "{0}Filename: {1}\n\n".format(report_str,json_dict['filename'])
    report_str = "{0}Total Domains: {1}\n\n".format(report_str,json_dict['total_domains'])
    report_str = "{0}Domains with none policy: {1}\n".format(report_str,json_dict['domains_none'])
    report_str = "{0}Domains with quarantine policy: {1}\n".format(report_str,json_dict['domains_quarantine'])
    report_str = "{0}Domains with reject policy: {1}\n\n".format(report_str,json_dict['domains_reject'])
    report_str = "{0}Messages Quarantined: {1}\n".format(report_str,json_dict['msgs_quarantined'])
    report_str = "{0}Messages Rejected: {1}\n\n".format(report_str,json_dict['msgs_rejected'])
    
    report_str = "{0}Top 20 domains rejected:\n".format(report_str)
    sorted_rejects = sorted(json_dict['domains_rejected'].items(), key=operator.itemgetter(1), reverse=True)
    for reject in sorted_rejects:
        report_str = "{0}    {1}: {2}\n".format(report_str,reject[0],reject[1])

    report_str = "{0}\nTop 20 domains quarantined:\n".format(report_str)
    sorted_quarantines = sorted(json_dict['domains_quarantined'].items(), key=operator.itemgetter(1), reverse=True)
    for quarantine in sorted_quarantines:
        report_str = "{0}    {1}: {2}\n".format(report_str,quarantine[0],quarantine[1])

    report_str = "{0}\nTop 20 domains none:\n".format(report_str)
    sorted_nones = sorted(json_dict['domains_noned'].items(), key=operator.itemgetter(1), reverse=True)
    for noned in sorted_nones:
        report_str = "{0}    {1}: {2}\n".format(report_str,noned[0],noned[1])

    report_str = "{0}\n\n---------------------------------------------------------------\n\n".format(report_str)

    return report_str


parser = argparse.ArgumentParser (description='Process command line flags')
parser.add_argument('--file', '-f', dest='filename', help='Filename to process', required=True)
parser.add_argument('--report', '-r', action='store_true', help='Output a human readable report')
parser.add_argument('--domain', '-d', dest='domain', help='Analyze a specific domain')
parser.add_argument('--field', '-i', dest='field', nargs=2, default=list(), help='Analyze a specific field value [field value]')
args = parser.parse_args()

analysis = parse_log(args.filename,args.domain,args.field)

if args.report:
    print generate_report(analysis)
else:
    print analysis
