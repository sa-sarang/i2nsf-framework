#ifndef __CONSTANTS__
#define __CONSTANTS__


#define bool int
#define true 1
#define false 0

#define SFF_INTERFACE "sff0"
#define NSF_INTERFACE "eth0"
#define BUF_LEN 128

/*-------------Inspection Result----------------*/
#define PASS 0x00000000
#define DENY 0x00000001
#define MIRROR 0x00000002
#define ADVANCED 0x00000003

/*-------------Metadata Code For Advanced Action-------------*/
#define DDOS_INSPECTION 0x00000000
#define DPI_INSPECTION 0x00000001

/*-------------IP Setting------------*/
#define SFF_IP "10.0.0.100"
#define ADMIN_IP "10.0.0.101"
#define FIREWALL_IP "10.0.0.200"
#define DPI_IP "10.0.0.102"
#define DNS_IP "192.168.91.2"
#define LOOP_BACK "127.0.0.1"

/*-------------Web Site---------------*/
#define FACEBOOK "10.0.0.201"
#define GOOGLE "10.0.0.202"
#define NAVER "10.0.0.203"
#define INSTAGRAM "10.0.0.204"


/*-------------Eployee IP---------------*/
#define STAFF_1 "10.0.0.2"
#define STAFF_2 "10.0.0.3"
#define MANAGER "10.0.0.14"
#define PRESIDENT "10.0.0.24"

/*-------------Eployee IP---------------*/
#define PHONE_OF_STAFF_1 "070-1234-0001@voip.kt.com"
#define PHONE_OF_STAFF_2 "070-1234-0002@voip.kt.com"
#define PHONE_OF_MANAGER "070-1234-1000@voip.kt.com"
#define PHONE_OF_PRESIDENT "070-1234-2000@voip.kt.com"

/*-------------Protocol Definition------------*/
#define SENDER_PROTOCOL 145
#define TUNNELING_PROTOCOL 146
#define UDP_PROTOCOL 17
#define ICMP_PROTOCOL 1
#define TCP_PROTOCOL 6
#define IGMP_PROTOCOL 2

/*-------------Running Interface Mode-----------------*/
#define SFF_MODE 0
#define FIREWALL_MODE 1
#define DDOS_MITIGATOR_MODE 2
#define DPI_MODE 3

/*-------------Currnet Time--------------------*/
#define CURRNET_TIME 12

/*-------------Service Port-------------------*/
#define VOIP 5060



#endif
