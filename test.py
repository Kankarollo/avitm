from scapy.all import sniff


def main():
    while True:
        print(sniff(count=1,iface='enp34s0',prn=lambda x:x.summary()))


if __name__ == '__main__':
    main()
    