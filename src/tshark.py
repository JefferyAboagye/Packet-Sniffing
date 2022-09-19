import subprocess, os, signal

def testTshark():
    returncode = subprocess.run([f'tshark --version'],
                            shell=True,stdout=subprocess.PIPE).returncode

    if returncode==0:
        print('tshark installed')
    else:
        print('tshark not installed')


def readPcaps2Csv(pcap_path, csv_name):
    '''read pcaps to csv.'''
    
    assert pcap_path.endswith('.pcap'), f'{pcap_path} needs to end with .pcap'
    assert csv_name.endswith('.csv'), f'{csv_name} needs to end with .csv'
    
    # 27 columns
    cmd = f"tshark -r {pcap_path} -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e frame.time_epoch -e frame.time -e frame.len -e ip.src -e ip.dst -e ip.len -e ip.flags.df -e ip.flags.mf \-e ip.fragment -e ip.fragment.count -e ip.fragments -e ip.ttl -e ip.proto -e tcp.window_size -e tcp.ack -e tcp.seq -e tcp.len -e tcp.stream -e tcp.urgent_pointer \-e tcp.flags -e tcp.analysis.ack_rtt -e tcp.segments -e tcp.reassembled.length -e http.request -e udp.port -e frame.time_relative -e frame.time_delta -e tcp.time_relative -e tcp.time_delta -e dns.qry.name > {csv_name}"
    subprocess.Popen([cmd], shell = True, stdout=subprocess.PIPE)


def capturePackets(output_name, interface='en0',num_packets=5, duration=120):
    '''Capture Packets with Tshark
        you can also use the “-c <n>” syntax to capture the “n” number of packets.
        
        duration flag to stop the process within 120 seconds, which is two minutes. [ -a duration:120 ]
        
        [ implement if need be ]
        if you don’t need your files to be extra-large, filesize is a perfect flag to
        stop the process after some KB’s limits.
                 [ -a filesize:50 ]
        
    '''
    
    if output_name.endswith('.pcap'):
        output_name = output_name.split('.')[0]
        
    if num_packets > 0:
        cmd = f'tshark -i {interface} -c {num_packets} -a duration:{duration}  -t ad host -w {output_name}.pcap'

    cmd = f'tshark -i {interface} -a duration:{duration} -w {output_name}.pcap'
    
    pro = subprocess.Popen([cmd],shell=True,stdout=subprocess.PIPE, preexec_fn=os.setsid)
    return pro

