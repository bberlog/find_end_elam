#!/usr/bin/env python

import re
import argparse
import xml.etree.cElementTree as ET
import sys
import json
import requests
import threading
import pexpect
import time

def run_commands(commands_list, hostname, password, output, exp_symbol='# ', waitcycles=10):
    """
    expect script - logs in to the node and, goes to the linecard and starts proper elam
    :param commands_list: list of elam related config
    :param hostname: hostname of the node to login to
    :param password:
    :param output: file pointer where to write
    :param exp_symbol: symbol we expect to see after we run any command
    :param waitcycles: how many 10 seconds cycles we need to wait before exit

    :return:
    """
    #login to the box:
    child = pexpect.spawn('ssh '+hostname)
    child.expect('Password:')
    child.sendline(password)
    child.expect(exp_symbol)
    child.sendline('vsh_lc')
    child.expect(exp_symbol)
    child.sendline('debug platform internal ns elam asic 0')
    child.expect(exp_symbol)
    for command in commands_list:
        child.sendline(command)
        child.expect(exp_symbol)
    child.sendline('terminal length 0')
    child.expect(exp_symbol)
    dummy_i = 0
    while dummy_i < waitcycles:
        child.sendline('status')
        child.expect(exp_symbol)
        #print hostname
        #print child.before
        if re.search('Status: Triggered', child.before):
            child.sendline('report')
            child.expect(exp_symbol)
            output.write(child.before)
            print 'Captured on '+hostname
            print 'See results in '+output.name
            return 1
        else:
            time.sleep(10)
            dummy_i += 1
    print 'Nothing was captured on switch '+hostname
    return 0

def auth(username,password):
    """
    Authenticate against apic
    :param username:
    :param password:
    :return: return dictionary with APIC cookie name as a key and APIC cookie as a value
    """
    url = 'http://localhost:7777/api/aaaLogin.json'
    auth_dict = {"aaaUser": {"attributes": {"name": username, "pwd": password}}}
    auth = requests.post(url, data=json.dumps(auth_dict))
    if auth.status_code != 200:
        raise ValueError('Could not authenticate. Most likely username/password are incorrect')
    else:
        return {'APIC-cookie': auth.cookies['APIC-cookie']}


def get_xml_root(url,cookie):

    """
    :param url: URL to pull with icurl
    :return: XML root from etree
    """
    req = requests.get(url, cookies=cookie)
    out = req.text

    try:
        ips_xml_root = ET.fromstring(out)
    except:
        print 'There is something wrong with XML output'
        raise
    return ips_xml_root


def get_all_ctx(ip_xml_root, node_dict, cookie):
    """

    :param ip_xml_root: XML root from etree
    :param node_dict: dictionary where node ID corresponds to Node name. For better UX
    :return: dictionary with ctx in format {ctx_scope:{'name':ctx_name,'list_of_nodes':['node1','node2'...]}}

    """
    list_of_ctx = {}
    for child in ip_xml_root.getiterator('epmIpEp'):
        if re.search('ctx-\[vxlan-\d+\]', child.attrib['dn']):
            dn_list = child.attrib['dn'].split('/')
            ctx_vxlan = re.search('(\d+)', dn_list[4]).group(0)
            if ctx_vxlan in list_of_ctx.keys():
                list_of_ctx[ctx_vxlan]['list_of_nodes'].append(node_dict[dn_list[2]])
            else:
                ctx_dn = '/'.join(child.attrib['dn'].split('/')[:5])
                url_send = 'http://localhost:7777/api/node/mo/'+ctx_dn+'.xml?query-target=self'
                ctx_name = get_xml_root(url_send, cookie).find('l3Ctx').attrib['name']
                list_of_nodes = [node_dict[dn_list[2]]]
                list_of_ctx[ctx_vxlan] = {'name': ctx_name, 'list_of_nodes': list_of_nodes}
    return list_of_ctx


def slct_ctx(ctx_dict, ip):
    """

    :param ctx_dict: dictionary in format returned by  get_all_ctx
    :return: distionary with only one key - selected context
    """
    print 'IP '+ip+' is found in more than one Ctx. Please select the one you need below'
    dummy_i = 1
    for ctx in ctx_dict.keys():
        print "["+str(dummy_i)+"] : "+ctx_dict[ctx]['name']
        dummy_i += 1
    while True:
        ctx_num = input("Please select number from 1 to "+str(len(ctx_dict.keys()))+": ")
        if isinstance(ctx_num, int) and 1 <= ctx_num <= len(ctx_dict.keys()):
            break
        else:
            pass
    ctx_vxlan = ctx_dict.keys()[int(ctx_num)-1]
    return {ctx_vxlan: ctx_dict[ctx_vxlan]}


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="search for EndPoint's IPs and generates ELAM config")
    parser.add_argument("-s", action="store", dest='ip_source', help='Source IP address')
    parser.add_argument("-d", action="store", dest='ip_destination', help='Destination IP address')
    parser.add_argument("-u", action="store", dest='username', help='Username')
    parser.add_argument("-p", action="store", dest='password', help='password')
    results = parser.parse_args()

    url_ips = 'http://localhost:7777/api/node/class/epmIpEp.xml?query-target-filter=and(eq(epmIpEp.addr,'+'\"'+results.ip_source+'\"))'
    url_ipd = 'http://localhost:7777/api/node/class/epmIpEp.xml?query-target-filter=and(eq(epmIpEp.addr,'+'\"'+results.ip_destination+'\"))'
    url_nodes = 'http://localhost:7777/api/node/class/fabricNode.xml?query-target-filter=and(eq(fabricNode.role,"leaf"))'

#build a dictionary of nodes, just for better UX later
    cookie = auth(results.username, results.password)
    print cookie
    node_dict = {}
    for node in get_xml_root(url_nodes, cookie).getiterator('fabricNode'):
        node_dict['node-'+str(node.attrib['id'])] = node.attrib['name']
    ips_ctx_dict = get_all_ctx(get_xml_root(url_ips, cookie), node_dict, cookie)
    ipd_ctx_dict = get_all_ctx(get_xml_root(url_ipd, cookie), node_dict, cookie)
    if len(ips_ctx_dict) == 0:
        sys.exit("Didn't find Source IP anywhere")
    elif len(ipd_ctx_dict) == 0:
        sys.exit("Didn't find Destination IP anywhere")
    else:
        if len(ips_ctx_dict) > 1:
            src_context = slct_ctx(ips_ctx_dict, results.ip_source)
        else:
            src_context = ips_ctx_dict
        if len(ipd_ctx_dict) > 1:
            dst_context = slct_ctx(ipd_ctx_dict, results.ip_destination)
        else:
            dst_context = ipd_ctx_dict

        src_commands = ['vsh_lc', 'debug platform internal ns elam asic 0',
                        'trigger init ingress in-select 3 out-select 0',
                        'set outer ipv4 src_ip '+results.ip_source+' dst_ip '+results.ip_destination,
                        'start']

        dst_commands = ['vsh_lc', 'debug platform internal ns elam asic 0',
                        'trigger init egress in-select 6 out-select 0',
                        'set inner ipv4 src_ip '+results.ip_source+' dst_ip '+results.ip_destination,
                        'start']

        threads = []
        for dummy_dev in src_context.itervalues().next()['list_of_nodes']:
            print "starting SRC ELAM on "+dummy_dev
            dummy_file = open('/tmp/elam-src-'+dummy_dev,'w')
            dummy_thread = threading.Thread(target=run_commands, args=(src_commands,dummy_dev,results.password,dummy_file,))
            threads.append(dummy_thread)
            dummy_thread.start()

        for dummy_dev in dst_context.itervalues().next()['list_of_nodes']:
            print "starting DST ELAM on "+dummy_dev
            dummy_file = open('/tmp/elam-dst-'+dummy_dev,'w')
            dummy_thread = threading.Thread(target=run_commands, args=(dst_commands,dummy_dev,results.password,dummy_file,))
            threads.append(dummy_thread)
            dummy_thread.start()
