from sniffer import Sniffer
from argparse import ArgumentParser
import logging
import os

log = logging.getLogger("mylog")
log.setLevel(logging.DEBUG)

def main():
    sniffer = Sniffer()
    try:
        sniffer.run()
    except KeyboardInterrupt as e:
        print(str(e))
        sniffer.stop()

def test():
    import subprocess
    IP_TEST = "192.168.0.130"
    # subprocess.call(["sudo" ,"iptables" ,"-A", "INPUT" ,"-s" ,IP_TEST ,"-j", "DROP"])
    # log.debug(f"[COMMAND:] sudo iptables -A OUTPUT -s {IP_TEST} -j DROP")
    subprocess.call(["sudo" ,"iptables" ,"-D", "INPUT" ,"-s" ,IP_TEST ,"-j", "DROP"])
    log.debug(f"[COMMAND:] sudo iptables -D OUTPUT -s {IP_TEST} -j DROP")
    print("[TEST] TEST!")

if __name__ == '__main__':
    parser =  ArgumentParser()
    parser.add_argument("filename", metavar='f', type=str, help="Filename of logging file.")

    args = parser.parse_args()

    # Log to file

    logfile_name = os.path.join(os.getcwd(),"logs",args.filename) 
    logfile_formatter = logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s")
    filehandler = logging.FileHandler(logfile_name)
    filehandler.setLevel(logging.DEBUG)
    filehandler.setFormatter(logfile_formatter)
    log.addHandler(filehandler)

    # Log to stdout too
    streamhandler = logging.StreamHandler()
    streamhandler.setLevel(logging.INFO)
    streamhandler.setFormatter(logfile_formatter)
    log.addHandler(streamhandler)

    main()
    # test()
