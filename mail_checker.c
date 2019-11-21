//DNS Query Program on Linux
//Author : Silver Moon (m00n.silv3r@gmail.com)
//Dated : 29/4/2009

//Header Files
#include <stdio.h>	//printf
#include <string.h>	//strlen
#include <stdlib.h>	//malloc
#include <sys/socket.h>	//you know what this is for
#include <arpa/inet.h>	//inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <unistd.h>	//getpid

#define A 1 //IPv4
#define MX 15 // mail 

//List of DNS Servers registered on the system
char dns_servers[10][100];
int dns_server_count = 0;
//Types of DNS resource records :)

//Function Prototypes
void ngethostbyname (unsigned char* , int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
void get_dns_servers();

//DNS header structure
struct DNS_HEADER
{
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of DNS_QUESTION entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct DNS_QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

//Pointers to resource record contents
struct DNS_ANSWER
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
	unsigned int preference;
};

// Main
int main( int argc , char *argv[])
{
	unsigned char hostname[100];
	unsigned char query_type[10];

	//Get the DNS servers from the resolv.conf file
	get_dns_servers();
	
	//Get the hostname from the terminal
	printf("Enter Hostname to Lookup : ");
	scanf("%sockfd" , hostname);

	ngethostbyname(hostname, MX);
	
	return 0;
}

/*
 * Perform a DNS query by sending a packet
 * */
void ngethostbyname(unsigned char *host , int query_type)
{
	unsigned char buf[65536];
	unsigned char *qname;
	unsigned char *reader;

	int sockfd;
	int j;
	int stop = 0;

	struct DNS_ANSWER answers[20];//the replies from the DNS server
	struct sockaddr_in dest;
	struct DNS_HEADER *dns_header = NULL;
	struct DNS_QUESTION *dns_question = NULL;

	sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(dns_servers[0]); //dns_header servers
	int dest_size = sizeof(dest);

	//Set the DNS structure to standard queries
	dns_header = (struct DNS_HEADER *)&buf;

	dns_header->id = (unsigned short) htons(getpid());
	dns_header->qr = 0; //This is a query
	dns_header->opcode = 0; //This is a standard query
	dns_header->aa = 0; //Not Authoritative
	dns_header->tc = 0; //This message is not truncated
	dns_header->rd = 1; //Recursion Desired
	dns_header->ra = 0; //Recursion not available!
	dns_header->z = 0;
	dns_header->ad = 0;
	dns_header->cd = 0;
	dns_header->rcode = 0;
	dns_header->q_count = htons(1); //we have only 1 DNS_QUESTION
	dns_header->ans_count = 0;
	dns_header->auth_count = 0;
	dns_header->add_count = 0;	

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
	
	ChangetoDnsNameFormat(qname , host);

	dns_question =(struct DNS_QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
	dns_question->qtype = htons(query_type); 
	dns_question->qclass = htons(1); 

	if(sendto(sockfd,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct DNS_QUESTION),0,(struct sockaddr*)&dest,dest_size) < 0)
	{
		printf("Error occured while sending packet");
	}

	if(recvfrom(sockfd,(char*)buf , 65536 , 0 , (struct sockaddr *)&dest, (socklen_t *)&dest_size) < 0)
	{
		printf("Error occured while receiving packet");
	}

	dns_header = (struct DNS_HEADER*) buf;

	//move ahead of the dns_header header and the query field
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct DNS_QUESTION)];

	for(dest_size = 0; dest_size < ntohs(dns_header->ans_count); dest_size++)
	{
		answers[dest_size].name = ReadName(reader,buf,&stop);
		reader = reader + stop;

		answers[dest_size].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);

		answers[dest_size].rdata = ReadName(reader,buf,&stop);
		reader = reader + stop;
	}

	unsigned int buf2[65536];
    printf("%d\n", ntohs(answers[0].resource->preference = *buf2));
	printf("%d\n", ntohs(answers[2].resource->preference = *buf2));

	//print answers
	for(dest_size=0 ; dest_size < ntohs(dns_header->ans_count) ; dest_size++)
    {
		printf("Mail server: %s \n", answers[dest_size].rdata);
	}
}

unsigned char* ReadName(unsigned char* reader, unsigned char* buffer, int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int dest_size , j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0]='\0';

	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader >= 192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else
		{
			name[p++]=*reader;
		}

		reader = reader+1;

		if(jumped==0)
		{
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}

	name[p]='\0'; //string complete
	if(jumped==1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	// convert 3www6google3com0 to www.google.com
	for(dest_size=0;dest_size < (int)strlen((const char*)name);dest_size++) 
	{
		p=name[dest_size];
		for(j=0;j < (int)p;j++) 
		{
			name[dest_size]=name[dest_size+1];
			dest_size=dest_size+1;
		}
		name[dest_size]='.';
	}

	name[dest_size-1]='\0'; //remove the last dot
	return name;
}

/*
 * Get the DNS servers from /etc/resolv.conf file on Linux
 * */
void get_dns_servers()
{
	FILE *fp;
	char line[200] , *p;
	fp = fopen("/etc/resolv.conf" , "r");
	
	while(fgets(line , 200 , fp))
	{
		if(line[0] == '#')
		{
			continue;
		}
		if(strncmp(line , "nameserver" , 10) == 0)
		{
			p = strtok(line , " ");
			p = strtok(NULL , " ");
		}
	}
	
	strcpy(dns_servers[0] , "208.67.222.222");
	strcpy(dns_servers[1] , "208.67.220.220");
}

/*
 * This will convert www.google.com to 3www6google3com 
 * */
void ChangetoDnsNameFormat(unsigned char* dns_header,unsigned char* host) 
{
	int lock = 0 , dest_size;
	strcat((char*)host,".");
	
	for(dest_size = 0 ; dest_size < strlen((char*)host) ; dest_size++) 
	{
		if(host[dest_size]=='.') 
		{
			*dns_header++ = dest_size-lock;
			for(;lock < dest_size;lock++) 
			{
				*dns_header++=host[lock];
			}
			lock++; 
		}
	}
	*dns_header++='\0';
}