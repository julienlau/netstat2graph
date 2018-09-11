#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
from __future__ import (absolute_import,
                        division,
                        print_function,
                        unicode_literals)

import os
import sys
import glob
import logging
import pygraphviz as pgv
import pandas as pd
import argparse
import hashlib

logger = logging.getLogger(__name__)
logging.basicConfig(filename=sys.argv[0][:-3] + '.log', filemode='w',
                    format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.DEBUG)


def etchostsparse(hostfile='/etc/hosts'):
    fio = open(hostfile, 'r')
    ip2host, host2ip = {}, {}
    for line in fio.readlines():
        if len(line) > 3 and line[0] != "#":
            spline = line.split()
            ip = spline[0]
            if ip not in ["127.0.0.1", "*", "0.0.0.0", "::1", "fe00::0", "ff00::0", "ff02::1", "ff02::2", "ff02::3"]:
                ip2host[ip] = spline[1]
                host2ip[spline[1]] = ip
    fio.close()
    return ip2host, host2ip


def string2numeric_hash(text):
    return int(hashlib.md5(text).hexdigest()[:8], 16)


def get_edge_color(src, dst):
    """
    define some custom colors for an edge based on its name and a dictionary of predefined colors
    """
    colorlist = ['gold', 'salmon', 'steelblue', 'firebrick', 'orchid', 'sienna', 'brown',
                 'blueviolet', 'blue', 'indigo', 'yellow', 'pink', 'violet', 'green', 'darkgreen',
                 'greenyellow', 'palegreen', 'magenta', 'orange', 'cyan', 'seagreen', 'gray',
                 'mediumturquoise', 'red']
    return colorlist[string2numeric_hash(src[:1] + '+' + dst[:1]) % (len(colorlist) - 1)]


def get_node_color(name):
    """
    define some custom colors for a node based on its name and a dictionary of predefined colors
    """
    colorlist = ['gold', 'salmon', 'steelblue', 'firebrick', 'orchid', 'sienna', 'brown',
                 'blueviolet', 'blue', 'indigo', 'yellow', 'pink', 'violet', 'green', 'darkgreen',
                 'greenyellow', 'palegreen', 'magenta', 'orange', 'cyan', 'seagreen', 'gray',
                 'mediumturquoise', 'red']
    return colorlist[string2numeric_hash(name.encode("utf-8")) % (len(colorlist) - 1)]


def netstat2graph(hostfile, infile, outfile):
    """
    This function forms a graph given the netstat log files.
    It writes a csv gathering the whole platform connections.
    It writes an image + a dot file for each host processed.

    :param hostfile: file that defines ip to host mapping
    :param infile: path to the directory containing the input file in format netstat-HOSTNAME.log
    :param outfile: suffix to be append to the output files.
    :return:
    """
    ip2host, host2ip = etchostsparse(hostfile)

    alldf = None
    listfiles = glob.glob(infile + '/netstat-*.log')
    for fnstat in listfiles:
        logger.info("Process a log file" + fnstat)

        # Create empty graph
        graph = pgv.AGraph(strict=False, directed=True)
        graph.graph_attr['label'] = 'Auto-generated with netstat2graph.py'
        # graph.graph_attr['rankdir'] = 'LR'

        # gather info on localhost
        currenthost = fnstat.split("netstat-")[-1].split(".log")[0]
        if currenthost in ip2host.keys():
            currenthost = ip2host[currenthost]
        else:
            ip2host[currenthost] = currenthost

        netdf = read_netstat(fnstat)
        netdf = df_resovle_ip(netdf, currenthost, ip2host)

        # Add nodes for surrounding
        # gPlateform = graph.subgraph(name='cluster' + 'platform', label='platform')
        for ip in ip2host.keys():
            hnameSrc = ip2host[ip]
            if hnameSrc != currenthost:  # currenthost will be a cluster
                graph.add_node(hnameSrc, label=hnameSrc,
                               color=get_node_color(hnameSrc), shape='box', style='filled')

        # Process currenthost
        gSrc = graph.subgraph(name='cluster' + currenthost, label=currenthost,
                              style='filled', color='lightgrey')
        for index, row in netdf.loc[netdf['State'] == "LISTEN"].iterrows():
            hnameSrc = row["LocalAddress"]
            nodeSrc = row["LocalPort"] + '/' + row["Netid"]
            gSrc.add_node(hnameSrc + '/' + nodeSrc, label=nodeSrc, rankdir='LR',
                          color=get_node_color(nodeSrc), shape="diamond", style='filled')

        # Process remaining sockets
        for index, row in netdf.loc[(netdf['State'] != "LISTEN") & (netdf['State'] != "TIME-WAIT")].iterrows():
            hnameSrc = row["LocalAddress"]
            hnameDst = row["PeerAddress"]
            # We do not want to draw the ip address of customers
            if hnameDst not in host2ip.keys():
                hnameDst = "WORLD"

            if hnameSrc == currenthost:
                labelSrc = row["LocalPort"] + '/' + row["Netid"]
                nameSrc = hnameSrc + '/' + labelSrc
                if not gSrc.has_node(nameSrc) and hnameDst != currenthost:
                    gSrc.add_node(nameSrc, color=get_node_color(nameSrc), label=labelSrc)
                    logger.debug(nameSrc)
            else:
                labelSrc = hnameSrc
                nameSrc = hnameSrc
                if not graph.has_node(nameSrc):
                    graph.add_node(nameSrc, color=get_node_color(nameSrc), label=labelSrc)
                    logger.debug(nameSrc)

            if hnameDst == currenthost:
                # labelDst = row["PeerPort"] + '/' + row["Netid"]
                # nameDst = hnameDst + '/' + labelDst
                # if not gSrc.has_node(nameDst):
                #     gSrc.add_node(nameDst, color=get_node_color(nameDst), label=labelDst)
                #     logger.debug(nameDst)
                pass
            else:
                labelDst = hnameDst
                nameDst = hnameDst
                if not graph.has_node(nameDst):
                    graph.add_node(nameDst, color=get_node_color(nameDst), label=labelDst,
                                   shape='diamond', style='filled')
                    logger.debug(nameDst)

            if not graph.has_edge(nameSrc, nameDst):
                if hnameSrc != hnameDst:  # do not draw sockets that are internal to the host
                    graph.add_edge(nameSrc, nameDst, color=get_edge_color(nameSrc, nameDst))
        # Processs a dataframe containing the whole host
        if alldf is None:
            alldf = netdf.copy()
        else:
            alldf = alldf.append(netdf)
        alldf.to_csv('platform' + '-' + outfile + '.csv')
        logger.info('platform' + '-' + outfile + '.csv')

        graph.layout(prog='dot')
        graph.draw(currenthost + '-' + outfile + '.png')
        logger.info("Wrote " + currenthost + '-' + outfile + '.png')
        graph.write(currenthost + '-' + outfile + '.dot')
        logger.info("Wrote " + currenthost + '-' + outfile + '.dot')
    return


def df_resovle_ip(netdf, hostname, ip2host):
    """
    :param netdf: dataframe. obtained by reading netstat file
    :param hostname: string.
    :param ip2host: dict
    :return: dataframe with resolved hostnames
    """
    netdf["LocalAddress"].replace("127.0.0.1", hostname, inplace=True)
    netdf["LocalAddress"].replace("0.0.0.0", hostname, inplace=True)
    netdf["LocalAddress"].replace("*", hostname, inplace=True)
    netdf["PeerAddress"].replace("127.0.0.1", hostname, inplace=True)
    netdf["PeerAddress"].replace("0.0.0.0", hostname, inplace=True)
    for ip in ip2host.keys():
        netdf["LocalAddress"].replace(ip, ip2host[ip], inplace=True)
        netdf["PeerAddress"].replace(ip, ip2host[ip], inplace=True)
    return netdf


def read_netstat(fnstat):
    """
    :param fnstat: file name of the netstat log file
    :return: dataframe
    """
    # read log of netstat
    pdnames = ["Netid", "State", "Recv-Q", "Send-Q", "Local Address:Port", "Peer Address:Port", "process"]
    rawdf = pd.read_table(fnstat, sep='\s+', header=None, skiprows=1, names=pdnames)

    # Transform dataframe to have proper column for port and ip
    ipPortSrc = rawdf[["Local Address:Port"]].stack().str.split(':', 1, expand=True)
    ipPortSrc.columns = ["LocalAddress", "LocalPort"]
    ipPortSrc.index = rawdf.index
    ipPortDst = rawdf[["Peer Address:Port"]].stack().str.split(':', 1, expand=True)
    ipPortDst.columns = ["PeerAddress", "PeerPort"]
    ipPortDst.index = rawdf.index
    netdf = rawdf.drop(columns=["Local Address:Port", "Peer Address:Port", "Recv-Q", "Send-Q"])
    netdf = pd.merge(netdf, ipPortSrc, left_index=True, right_index=True)
    netdf = pd.merge(netdf, ipPortDst, left_index=True, right_index=True)
    return netdf


def netstat2graph_input():
    """
    routine that gets user inputs
    """
    parser = argparse.ArgumentParser(description="""Draw a graph of all connections of a system of hosts based 
    on log files obtained by running `ss -natpu -4` on each host.
    For example, given a list of hosts the log could be gathered with the following command:

    `for dest in $mylistSsh; do ssh root@$dest "ss -natpu -4 " > logs/netstat-$dest.log ; done`
  
    It writes a csv gathering the whole platform connections.
    It writes an image + a dot file for each host processed.
    Nodes in diamond shapes represent LISTEN sockets. 
    """)
    parser.add_argument("-i", "--input", default='logs',
                        help="path to a directory containing the netstat log of hosts. "
                             "Files should be named netstat-*.log")
    parser.add_argument("--hosts", default='/etc/hosts',
                        help="optional path to a host file describing ip to host mapping.")
    parser.add_argument("-o", "--output", default='network', help="suffix of the output files")
    args = parser.parse_args()
    infile = args.input
    hostfile = args.hosts
    outfile = args.output
    if not os.path.isdir(infile):
        parser.print_help()
        raise Exception("Input file not specified")

    logger.info("START")
    netstat2graph(hostfile, infile, outfile)
    logger.info("END")
    return


if __name__ == "__main__":
    netstat2graph_input()
