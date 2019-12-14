#include <stdio.h>	
#include <string.h>	// strlen
#include <stdlib.h>	// malloc
#include <sys/socket.h>	
#include <arpa/inet.h>	// inet_addr, inet_ntoa, ntohs etc
#include <netinet/in.h>
#include <unistd.h>	// getpid, sleep
#include <ctype.h> // isprint

#define A 1 // ipv4
#define MX 15 // mail 
#define END 1 // end line

int Stop;
char Dns_Server[10][100];
unsigned char Email_Site[100] = "gmail.com";

unsigned char* ReadData (unsigned char*, unsigned char*);
unsigned char* GetDnsInfo (unsigned char*, char*, int);
int ReadBufferResponseCode(char*, char*, char*);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
void GetDnsServerFromFile();
void StartTelnet(char*, char*, char*);
void CheckResponseCode(char*, char*, char*);

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
	char user_to_check[50];
	unsigned char query_type[10];
	unsigned char dns_response_email_server[50];
	void* data_to_free;

	GetDnsServerFromFile();
	
	printf("Enter Username to Lookup: ");
	scanf("%sockfd", user_to_check);
	printf("\n");

	data_to_free = GetDnsInfo(Email_Site, NULL, MX);
	strncpy((char*)dns_response_email_server, (const char*)data_to_free, sizeof(dns_response_email_server));
	free(data_to_free);

	GetDnsInfo(dns_response_email_server, user_to_check, A);

	return 0;
}

unsigned char* GetDnsInfo(unsigned char* email_info, char* user_to_check, int query_type)
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
	
	ChangetoDnsNameFormat(qname, email_info);

	dns_question = (struct DNS_QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; 
	dns_question->qtype = htons(query_type); 
	dns_question->qclass = htons(1); 

	if(sendto(sockfd,(char*)buf, sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct DNS_QUESTION), 0, (struct sockaddr*)&dest,dest_size) < 0)
	{
		perror("Error occured while sending packet");
		exit(EXIT_FAILURE);
	}

	if(recvfrom(sockfd,(char*)buf, sizeof(buf), 0, (struct sockaddr *)&dest, (socklen_t *)&dest_size) < 0)
	{
		perror("Error occured while receiving packet");
		exit(EXIT_FAILURE);
	}

	dns_header = (struct DNS_HEADER*) buf;
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)) + sizeof(struct DNS_QUESTION)];

	answers[0].name = ReadData(reader, buf);
	free(answers[0].name);
	reader = reader + Stop;

	answers[0].resource = (struct R_DATA*)(reader);
	reader = reader + sizeof(struct R_DATA);

	if (query_type == MX)
	{
		reader = reader + Stop;
		answers[0].rdata = ReadData(reader, buf);

		printf("DNS mail server: %s\n", answers[0].rdata);

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
		StartTelnet(inet_ntoa(dest.sin_addr), user_to_check, (char*)email_info);
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

	host[dest_size - 1] = '\0';
}

void StartTelnet(char* ip_address, char* user_to_check, char* email_server)
{
	char* user;
	user = (char*)malloc(sizeof(user_to_check) * (strlen(user_to_check)));
	strncpy(user, user_to_check, sizeof(user_to_check) + END);

	char server_greeting[100];
	char rcpt_to[100];
	char server_quit[10];
	const char* mail_from = "mail from:<example@example.com>";
	const char* next_row = "\r\n";

	struct sockaddr_in telnet_addr;
	telnet_addr.sin_family = AF_INET;
	telnet_addr.sin_port = htons(25);
	telnet_addr.sin_addr.s_addr = inet_addr((const char*)ip_address);

	char buf[65536];

	printf("Connecting to email server...\n");
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(connect(sockfd, (struct sockaddr*)&telnet_addr, (socklen_t)sizeof(telnet_addr)) < 0)
	{
		perror("Connection error\n");            
		exit(EXIT_FAILURE);
	} 	 		
	printf("\033[1;32m\nConnected to %s\033[0m\n", email_server, ip_address);

	// Helo
	snprintf((char*)server_greeting, strlen("HELO ") + strlen(email_server) + END, "%s%s", "HELO ", email_server);
	// Rcpt to
	snprintf((char*)rcpt_to, strlen("rcpt to:") + strlen(user_to_check) + strlen("<>") + strlen((const char*)Email_Site) + strlen("@") + END, "%s%s%s%s%s%s", "rcpt to:<", user_to_check, "@", Email_Site, ">");
	// Quit
	snprintf((char*)server_quit, strlen("QUIT") + END, "%s", "QUIT");
	// Combine in buffer
	snprintf((char*)buf, 2048, "%s\r\n%s\r\n%s\r\n%s\r\n", server_greeting, mail_from, rcpt_to, server_quit);

	if(send(sockfd, (char*)buf, 2048, 0) < 0)
	{
		perror("Error occured while sending telnet query\n");
		exit(EXIT_FAILURE);
	}
	
	if(recv(sockfd, (char*)buf, 2048, MSG_WAITALL) < 0)
	{
		perror("Error occured while receiving telnet query\n");
		exit(EXIT_FAILURE);
	}

	close(sockfd);

	ReadBufferResponseCode(buf, user_to_check, rcpt_to);
	free(user);
}

int ReadBufferResponseCode(char* buf, char* user, char* email)
{
	int responseNumLength;
	int line_number = 1;
	int possible_end = 0;
	int buf_length = strlen((char*)buf);
	char firstThreeNums[3];
	char line[buf_length];
	char* p;
	int j = 0;

	for(int i = 0; i < buf_length; i++)
	{
		p = &buf[i];
		line[i] = *p;
		if(line_number == 4)
		{
			if(i < responseNumLength)
			{
				firstThreeNums[j] = line[i];
				j++;

				if(i == responseNumLength - 1)
				{
					firstThreeNums[j] = '\0';
					CheckResponseCode(firstThreeNums, user, email);
				}		
			}
		}

		if(line[i] == '\r' || possible_end == 1)
		{
			if(line[i] == '\n' && possible_end == 1)
			{
				possible_end = 0;
				line_number++;
				if(line_number == 4)
				{
					responseNumLength = i + 4;
				}
			}
			else
			{
				if(possible_end == 1)
				{
					possible_end = 0;
				}
				else
				{
					possible_end = 1;
				}
				
			}
		}
	}

	return 0;
}

void CheckResponseCode(char* code, char* user, char* mail_to_check)
{
	if(strcmp("553", code) == 0)
	{
		printf("\033[1;31mThe mail %s is not a valid RFC-5321 address, PLEASE USE ONLY username before '@' symbol!\033[0m\n", mail_to_check);
		exit(-1);
	}
	else if(strcmp("550", code) == 0)
	{
		printf("User account %s does not exist on %s\n", user, Email_Site);
	}
	else if(strcmp("250", code) == 0)
	{
		printf("\033[0;32mUser %s exists on %s!\033[0m\n", user, Email_Site);
	}
	else if(strcmp("", code) == 0)
	{
		printf("No response code from server... \n", Email_Site);	
	}
	else	
	{
		printf("Unknown code %s response\n", code);
	}
}