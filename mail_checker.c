#include <stdio.h>	
#include <string.h>	// strlen
#include <stdlib.h>	// malloc
#include <sys/socket.h>	
#include <arpa/inet.h>	// inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <unistd.h>	// getpid
#include <ctype.h> // isprint

#define A 1 // ipv4
#define MX 15 // mail 

int Stop;
char Dns_Server[10][100];

unsigned char* ReadData (unsigned char*, unsigned char*);
unsigned char* GetDnsInfo (unsigned char*, int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
void GetDnsServerFromFile();
void StartTelnet(char*, unsigned char*);

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

// Constant sized fields of query structure
struct DNS_QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

// Pointers to resource record contents
struct DNS_ANSWER
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

#pragma pack(push, 1)
struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

int main( int argc , char *argv[])
{
	unsigned char hostname[100];
	unsigned char query_type[10];
	unsigned char dns_response_email[50];
	void* data_to_free;

	GetDnsServerFromFile();
	
	printf("Enter Hostname to Lookup: ");
	scanf("%sockfd" , hostname);
	printf("\n");

	data_to_free = GetDnsInfo(hostname, MX);
	strncpy((char*)dns_response_email, (const char*)data_to_free, sizeof(dns_response_email));
	free(data_to_free);

	GetDnsInfo(dns_response_email, A);

	return 0;
}

unsigned char* GetDnsInfo(unsigned char *host , int query_type)
{
	unsigned char buf[65536], *qname, *reader;

	struct DNS_ANSWER answers[20]; //the replies from the DNS server
	struct DNS_HEADER *dns_header = NULL;
	struct DNS_QUESTION *dns_question = NULL;
	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(Dns_Server[0]); // dns_header servers

	int dest_size = sizeof(dest);
	int sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

	//Set the DNS structure to standard queries
	dns_header = (struct DNS_HEADER *)&buf;

	dns_header->id = (unsigned short) htons(getpid());
	dns_header->qr = 0; // query
	dns_header->opcode = 0; // standard query
	dns_header->aa = 0; // not authoritative
	dns_header->tc = 0; // not truncated
	dns_header->rd = 1; // recursion desired
	dns_header->ra = 0; // recursion not available
	dns_header->z = 0;
	dns_header->ad = 0;
	dns_header->cd = 0;
	dns_header->rcode = 0;
	dns_header->q_count = htons(1); //we have only 1 DNS_QUESTION
	dns_header->ans_count = 0;
	dns_header->auth_count = 0;
	dns_header->add_count = 0;	

	// point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
	
	ChangetoDnsNameFormat(qname, host);

	dns_question =(struct DNS_QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; 
	dns_question->qtype = htons(query_type); 
	dns_question->qclass = htons(1); 

	if(sendto(sockfd,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct DNS_QUESTION),0,(struct sockaddr*)&dest,dest_size) < 0)
	{
		perror("Error occured while sending packet");
		exit(EXIT_FAILURE);
	}

	if(recvfrom(sockfd,(char*)buf , 65536 , 0 , (struct sockaddr *)&dest, (socklen_t *)&dest_size) < 0)
	{
		perror("Error occured while receiving packet");
		exit(EXIT_FAILURE);
	}

	dns_header = (struct DNS_HEADER*) buf;
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)) + sizeof(struct DNS_QUESTION)];

	answers[0].name=ReadData(reader, buf);
	free(answers[0].name);
	reader = reader + Stop;

	answers[0].resource = (struct R_DATA*)(reader);
	reader = reader + sizeof(struct R_DATA);

	if (query_type == MX)
	{
		reader = reader + Stop;
		answers[0].rdata = ReadData(reader,buf);

		printf("Mail: %s\n", answers[0].rdata);

	    close(sockfd);
		return answers[0].rdata;
	}
	else if(query_type == A)
	{		
		for(int j = 0; j < ntohs(answers[0].resource->data_len); j++)
		{
			answers[0].rdata[j]=reader[j];
		}

		answers[0].rdata[ntohs(answers[0].resource->data_len)] = '\0';

		reader = reader + ntohs(answers[0].resource->data_len);

		long* p = (long*)answers[0].rdata;
		dest.sin_addr.s_addr=(*p);

		// Let's talk to server
		StartTelnet(inet_ntoa(dest.sin_addr), host);
	}

	return 0;
}

unsigned char* ReadData(unsigned char* reader, unsigned char* buffer) 
{
	unsigned char *data = (unsigned char*)malloc(256);
	unsigned int p = 0, jumped = 0, offset, dest_size;
	Stop = 1;

	// read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader >= 192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; // 49152 = 11000000 00000000 
			reader = buffer + offset - 1;
			jumped = 1; // we have jumped to another location so counting wont go up
		}
		else
		{
			data[p++]=*reader;
		}

		reader = reader+1;

		if(jumped==0)
		{
			Stop = Stop + 1; //if we havent jumped to another location then we can Stop up
		}
	}

	data[p]='\0'; //string complete
	
	if(jumped==1)
	{
		Stop = Stop + 1; //number of steps we actually moved forward in the packet
	}

	// convert 3www6google3com0 to www.google.com
	for(dest_size=0;dest_size < (int)strlen((const char*)data);dest_size++) 
	{
		if(!isprint(data[dest_size]))
		{
			data[dest_size] = '.';
		}
	}

	return data;
}

/*
 * Get the DNS servers from /etc/resolv.conf file on Linux
 * */
void GetDnsServerFromFile()
{
	const char default_dns_server[10] = "8.8.8.8";
	FILE *fp = fopen("/etc/resolv.conf" , "r");
	char line[200], *p;

	while(fgets(line , 100, fp))
	{
		if(line[0] == '#')
		{
			continue;
		}
		else if(strncmp(line , "nameserver" , 10) == 0)
		{
			p = strtok(line , " ");
			p = strtok(NULL , " ");
			strncpy(Dns_Server[0], p, strlen(p));
			return;
		}
	}

	printf("No registered dns servers found in system, using default google dns...\n\n");
	strncpy((char*)Dns_Server, default_dns_server, sizeof(default_dns_server));
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

void StartTelnet(char* address, unsigned char* email_server)
{
	char buf[65536];
	char telnet_query[100];
	int nbytes;

	struct sockaddr_in telnet_addr;
	telnet_addr.sin_family = AF_INET;
	telnet_addr.sin_port = htons(25);
	telnet_addr.sin_addr.s_addr = inet_addr((const char*)address);

	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	printf("Connecting to email server...\n");
	if(connect(sockfd, (struct sockaddr*)&telnet_addr, (socklen_t)sizeof(telnet_addr)) < 0)
	{
		perror("Connection error");
		exit(EXIT_FAILURE);
	}
	else
	{
		printf("\033[0;32m");
		printf("Connected to %s with ip %s!\n", email_server, address);
		printf("\033");
	}
	
	// TODO: make query sending to work
	
	// if(sendto(sockfd,(char*)buf,sizeof(buf), 0, (struct sockaddr*)&address, strlen(address)) < 0)
	// {
	// 	perror("Error occured while sending telnet query");
	// 	exit(EXIT_FAILURE);
	// }
	// if(recvfrom(sockfd,(char*)buf , 65536 , 0 , (struct sockaddr *)&dest, (socklen_t *)&dest_size) < 0)
	// {
	// 	perror("Error occured while receiving telnet query");
	// 	exit(EXIT_FAILURE);
	// }
	close(sockfd);
}