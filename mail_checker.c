#include <stdio.h>	
#include <string.h>	// strlen
#include <stdlib.h>	// malloc
#include <sys/socket.h> // sockets	
#include <sys/types.h> // size_t etc.
#include <sys/stat.h> // stat, fstat
#include <arpa/inet.h>	// inet_addr, inet_ntoa, ntohs etc
#include <netinet/in.h>
#include <ctype.h> // isprint, isdigit, isalpha
#include <unistd.h> // getpid
#include <argp.h> // CL args handling

#define MAX_MAIL_LENGTH 254 // Max length for email according to RFC 
#define MAX_USERNAME_LENGTH 64 // Max length for username according to RFC
#define A 1 // IPv4 query type
#define A_POSITION 2 // A record position in packet
#define MX 15 // Mail query type
#define MX_POSITION 5 // MX record position in packet
#define END 1 // End line

// CL args in flag format, can be 0 either 1
unsigned int USER_PROVIDED_FLAG;
unsigned int VERBOSITY_LEVEL; // 1, 2
unsigned int READ_MAILS_FROM_FILE_FLAG;
unsigned int CHECK_ONE_MAIL_FLAG;
// unsigned int CONNECT_TO_EACH_SITES_MAIL_SERVER; // Do we want to connect to each sites server, that we want to check, or it is enough to do checks from single server
unsigned int CHANGE_DEFAULT_DNS_SERVER_FLAG;

// Only mandatory globals
char Dns_Server[32];
char Without_Variable[1] = "";

// Prototypes
int ReadBufferResponseCode(char*, char*, char*);
unsigned char* ReadDnsData(unsigned char*, unsigned char*);
unsigned char* GetDnsInfo(unsigned char*, int);
void WhomToCheck(char*);
void GetDnsServerFromFileOrSetDefault();
void StartTelnet(char*, char*, unsigned char*, char*);
void ChangeFormatToDNSFormat (unsigned char*, unsigned char*);
void ReadMailsFromFileAndExecuteCoreLogic(FILE*, char*);
void CoreLogic(char*, unsigned char*);
void CheckResponseCode(char*, char*, char*);
void PrintDebugInfoBasedOnVerbosityLevel(const char*, char*, unsigned int);

// Info for argp
const char* argp_program_bug_address = "daniklogan@gmail.com";
const char* argp_program_version = "Alpha 1.0";
static char doc[] = "\nBE CAUTIOUS! This program is using unsafe method to check mail for existence, "
					"by using this program too much you can end up with IP address in mail blacklist, while using this program, use also VPN/Gateway with dynamic IP etc "
					" This program is not checking, if user exists on site, works only with mail services!";
static char args_doc[] = "-u someuser -m mail [optional options]";

// Arguments for argp
struct CL_Arguments
{
	FILE* file;
	char* user_to_check;
	unsigned char* mail;
	char* desired_dns_server;
};

// Argp parser, input handler
static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
	struct CL_Arguments* CL_Arguments = (struct CL_Arguments*)state->input;

	switch(key)
	{
		case 'u':
		{
			if(strlen(arg) > MAX_USERNAME_LENGTH || strlen(arg) < 1)
			{
				argp_failure(state, 1, 0, "Username length cannot be more than 64 or less than 1 chars.");
			}

			CL_Arguments->user_to_check = arg;
			USER_PROVIDED_FLAG = 1;
		}
		break;

		case 'm':
		{
			if(strlen(arg) > MAX_MAIL_LENGTH || strlen(arg) < 1)
			{
				argp_failure(state, 1, 0, "Mail length cannot be more than 254 or less or 1 chars.");
			}

			CL_Arguments->mail = (unsigned char*)arg;
			CHECK_ONE_MAIL_FLAG = 1;
		}
		break;

		case 'v':
		{
			if(!isdigit(*arg))
			{
				printf("-v option must have a argument of number type\n");
				exit(1);
			}

			VERBOSITY_LEVEL = atoi(arg);
			if(VERBOSITY_LEVEL > 2)
			{
				VERBOSITY_LEVEL = 2;
			}

		}
		break;

		// case 'c':
		// {
		// 	CONNECT_TO_EACH_SITES_MAIL_SERVER = 1; // Not implemented, used by default
		// }
		// break;

		case 'd':
		{
			if(arg != NULL)
			{
				char* p;
				unsigned int dots = 0;
				for(size_t pos = 0; pos < strlen(arg); pos++)
				{
					p = &arg[pos];
					if(*p == '.')
					{
						dots++;
					}
					else if(!isdigit(*p) || !isprint(*p))
					{
						argp_failure(state, 1, 0, "Wrong address for -d option, argument must be digit.");
					}
				}

				if(dots != 3)
				{
					argp_failure(state, 1, 0, "Wrong address for -d option, must be IPv4, format '8.8.8.8'");
				}

				CL_Arguments->desired_dns_server = arg;
				CHANGE_DEFAULT_DNS_SERVER_FLAG = 1;
			}			
		}
		break;

		case 'f':
		{
			struct stat status;
			FILE* fp = fopen(arg, "r");
			if(fp == NULL)
			{
				printf("File error\n");
				exit(1);
			}
			else if(stat(arg, &status) != 0 || S_ISDIR(status.st_mode) != 0)
			{
				printf("Invalid file type\n");
				exit(1);
			}

			READ_MAILS_FROM_FILE_FLAG = 1;
			CL_Arguments->file = fp;
		}
		break;

		case ARGP_KEY_END:
		{
			if(!USER_PROVIDED_FLAG || (!CHECK_ONE_MAIL_FLAG && !READ_MAILS_FROM_FILE_FLAG))
			{
				argp_usage(state);
				exit(1);
			}
		}
		break;
	}

	return 0;
}

#pragma GCC diagnostic push 
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
struct argp_option options[] = 
{
	{ 0, 0, 0, 0, "Mandatory CL_Arguments:", 6 },
	{ 0, 'u', "[username]", 0, "Username to check", 6},
	{ 0, 'm', "[mail site]", 0, "Single site to check on, or use -f", 6 },
	{ 0, 'f', "[path to file]", 0, "Check every mail in format 'gmail.com' from file", 6 },
	{ 0, 0, 0, 0, "Optional CL_Arguments:", 7 },
	{ 0, 'd', "[IPv4 address]", 0, "Change default dns server", 7 },
	// { 0, 'c', 0, 0, "Connect to each sites mail server", 7 },
	{ "verbose", 'v', "[number]", 0, "Show debug info", 7 },
	{ 0 }
};

static struct argp argp = { options, parse_opt, args_doc, doc };
#pragma GCC diagnostic pop

// DNS header structure
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

// Contains data
#pragma pack(push, 1)
struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};
#pragma pack(pop)

// MAIN FUNCTION
int main(int argc, char *argv[])
{
	struct CL_Arguments CL_Arguments;
	// Check for positions and mandatory CL_Arguments, last check before start
	if(argp_parse(&argp, argc, argv, 0, 0, &CL_Arguments) == 0)
	{
		if(strcmp(argv[1], "-u") != 0 ||
		  (strcmp(argv[3], "-m") && strcmp(argv[3], "-f") != 0))
		{
			printf("Usage: %s\n", args_doc);
			return 0;
		}
	}
	else
	{
		printf("Usage: %s\n", args_doc);
		return 0;
	}

	// Reminder
	printf("Reminder: This program is not checking, if user exists on website!\n");
	
	// Get DNS server where to connect and send queries	
	GetDnsServerFromFileOrSetDefault();

	// Branching based on flags
	if(READ_MAILS_FROM_FILE_FLAG) // User chose -f option
	{
		ReadMailsFromFileAndExecuteCoreLogic(CL_Arguments.file, CL_Arguments.user_to_check);
	}
	else if(CHECK_ONE_MAIL_FLAG) // User chose -m option
	{
		CoreLogic(CL_Arguments.user_to_check, CL_Arguments.mail);
	}

	return 0;
}

// Get MX or IPv4 record from DNS
unsigned char* GetDnsInfo(unsigned char* email_info, int query_type)
{
	unsigned char buf[65536], *qname, *reader;
	int udp_packet_size = 512;

	struct DNS_ANSWER answers[20]; // The replies from the DNS server
	struct DNS_HEADER *dns_header = NULL;
	struct DNS_QUESTION *dns_question = NULL;
	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(Dns_Server); // DNS_HEADER servers

	int dest_size = sizeof(dest);
	int sockfd = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); 

	// Set the DNS structure to standard queries
	dns_header = (struct DNS_HEADER *)&buf;

	dns_header->id = (unsigned short) htons(getpid());
	dns_header->qr = 0; // Query
	dns_header->opcode = 0; // Standard query
	dns_header->aa = 0; // Not authoritative
	dns_header->tc = 0; // Not truncated
	dns_header->rd = 1; // Recursion desired
	dns_header->ra = 0; // Recursion not available
	dns_header->z = 0;
	dns_header->ad = 0;
	dns_header->cd = 0;
	dns_header->rcode = 0;
	dns_header->q_count = htons(1); // We have only 1 DNS_QUESTION
	dns_header->ans_count = 0;
	dns_header->auth_count = 0;
	dns_header->add_count = 0;	

	// Point to the query portion
	qname = (unsigned char*)&buf[sizeof(struct DNS_HEADER)];
	ChangeFormatToDNSFormat(qname, email_info);
	
	dns_question = (struct DNS_QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; 
	dns_question->qtype = htons(query_type); 
	dns_question->qclass = htons(1); 

	if(sendto(sockfd, (char*)buf, udp_packet_size, 0, (struct sockaddr*)&dest, (socklen_t)dest_size) < 0)
	{
		perror("Error occured while sending packet");
		exit(EXIT_FAILURE);
	}
	if(recvfrom(sockfd,(char*)buf, udp_packet_size, 0, (struct sockaddr*)&dest, (socklen_t*)&dest_size) < 0)
	{
		perror("Error occured while receiving packet");
		exit(EXIT_FAILURE);
	}

	dns_header = (struct DNS_HEADER*) buf;	
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct DNS_QUESTION)];

	answers[0].resource = (struct R_DATA*)reader; // Setting structure
	reader += sizeof(struct R_DATA);

	if (query_type == MX) // We want mail server 
	{
		reader += MX_POSITION; 
		answers[0].rdata = ReadDnsData(reader, buf);
		if(strlen((char*)answers[0].rdata) == 0)
		{
			reader += MX_POSITION; // Packet has other structure, need to advance further
	 		answers[0].rdata = ReadDnsData(reader, buf);
		}

	    close(sockfd);
		return answers[0].rdata;	
	}
	else if(query_type == A) // We want IPv4 address of mail server 
	{	
		reader += A_POSITION; 
		for(unsigned int j = 0; j < ntohs(answers[0].resource->data_len); j++)
		{
			answers[0].rdata[j] = reader[j];
		}

		answers[0].rdata[ntohs(answers[0].resource->data_len)] = '\0';
		reader = reader + ntohs(answers[0].resource->data_len);
		long* p = (long*)answers[0].rdata;
		dest.sin_addr.s_addr=(*p);

		close(sockfd);

		return (unsigned char*)inet_ntoa(dest.sin_addr);
	}

	return 0;
}

// Reading DNS Answer and returning data in readable format
unsigned char* ReadDnsData(unsigned char* reader, unsigned char* buffer) 
{
	unsigned char* data;
	int p = 0, offset;
	size_t dest_size;

	// Read the names in 3www6google3com format
	while(*reader != 0)
	{
		if(*reader >= 192)
		{
			offset = (*reader)*256 + *(reader + 1) - 49152; // 49152 = 11000000 00000000 
			reader = buffer + offset - 1;
		}
		else
		{
			data[p++] = *reader;
		}

		reader += 1;
	}

	data[p] = '\0'; 
	
	// Convert 3www6google3com0 to www.google.com
	for(dest_size = 0; dest_size < strlen((const char*)data); dest_size++) 
	{
		if(!isprint(data[dest_size]))
		{
			data[dest_size] = '.';
		}
	}

	return data;
}	

// Get the DNS servers from /etc/resolv.conf file on Linux or set default
void GetDnsServerFromFileOrSetDefault()
{
	const char default_dns_server[] = "8.8.8.8"; // Default google DNS
	FILE *fp = fopen("/etc/resolv.conf", "r");
	char line[50], *p;
	while(fgets(line , 50, fp))
	{
		if(line[0] == '#')
		{
			continue;
		}
		else if(strncmp(line , "nameserver" , 10) == 0)
		{
			p = strtok(line , " ");
			p = strtok(NULL , " ");
			strncpy(Dns_Server, p, strlen(p));
			return;
		}
	}

	printf("No registered dns servers found in system, using default google dns...\n\n");
	strncpy((char*)Dns_Server, default_dns_server, strlen(default_dns_server) + END);
}

// Converting www.google.com to DNS format 3www6google3com 
void ChangeFormatToDNSFormat(unsigned char* dns_header, unsigned char* host) 
{
	unsigned int lock = 0;
	size_t dest_size;
	strcat((char*)host, ".");
	for(dest_size = 0 ; dest_size < strlen((char*)host); dest_size++) 
	{
		if(host[dest_size]=='.') 
		{
			*dns_header++ = dest_size-lock;
			for(;lock < dest_size; lock++) 
			{
				*dns_header++ = host[lock];
			}
			lock++; 
		}
	}

	*dns_header++='\0';

	host[dest_size - END] = '\0';
}

// Start connection to email server through telnet protocol
void StartTelnet(char* ip_address, char* user_to_check, unsigned char* email_server, char* email_site) 
{
	char server_greeting[100];
	char rcpt_to[MAX_USERNAME_LENGTH + MAX_MAIL_LENGTH];
	char server_quit[10];
	const char* mail_from = "MAIL FROM:<example@example.com>"; // Default mail as sender, can be any, since we are not sending actual messages, unless you use this program for spam :)

	struct sockaddr_in telnet_addr;
	telnet_addr.sin_family = AF_INET;
	telnet_addr.sin_port = htons(25);
	telnet_addr.sin_addr.s_addr = inet_addr((const char*)ip_address);

	char buf[65536];
	unsigned int max_size = 512;

	PrintDebugInfoBasedOnVerbosityLevel("User To Check :::: ", user_to_check, 0);
	PrintDebugInfoBasedOnVerbosityLevel("Email site :::: ", email_site, 0); 
	PrintDebugInfoBasedOnVerbosityLevel("Email server :::: ", (char*)email_server, 1);
	PrintDebugInfoBasedOnVerbosityLevel("Server IPv4 :::: ", ip_address, 1);

	// Start connection
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	PrintDebugInfoBasedOnVerbosityLevel("\nConnecting to email server :::: ", (char*)email_server, 1);
	if(connect(sockfd, (struct sockaddr*)&telnet_addr, (socklen_t)sizeof(telnet_addr)) < 0)
	{
		perror("Connection error\n");            
		exit(EXIT_FAILURE);
	} 	 		
	printf("\033[0;32mConnected to %s\n\033[0m", email_site); // On any level

	// Helo stage
	snprintf((char*)server_greeting, strlen("HELO ") + strlen((const char*)email_server) + END, "%s%s", "HELO ", email_server);
	// Rcpt to stage
	snprintf((char*)rcpt_to, strlen("RCPT TO: ") + strlen((const char*)user_to_check) + strlen("<@>") + strlen((const char*)email_site) + END, "%s%s%s%s%s", "RCPT TO:<", user_to_check, "@", email_site, ">");
	// Quit stage
	snprintf((char*)server_quit, strlen("QUIT") + END, "%s", "QUIT");
	// Combine all stages in buffer
	snprintf((char*)buf, max_size, "%s\r\n%s\r\n%s\r\n%s\r\n", server_greeting, mail_from, rcpt_to, server_quit);

	// Send stage~
	PrintDebugInfoBasedOnVerbosityLevel("Sending query... this could take a while", Without_Variable, 0);
	if(send(sockfd, (char*)buf, max_size, 0) < 0)
	{
		perror("Error occured while sending telnet query:");
		exit(EXIT_FAILURE);
	}
	PrintDebugInfoBasedOnVerbosityLevel("Sended query: \n", buf, 2);

	// Receive stage
	PrintDebugInfoBasedOnVerbosityLevel("Getting response...", Without_Variable, 0);
	if(recv(sockfd, (char*)buf, max_size, MSG_WAITALL) < 0)
	{
		perror("Error occured while receiving telnet query:");
		exit(EXIT_FAILURE);
	}
	PrintDebugInfoBasedOnVerbosityLevel("Got response: \n", buf, 2);

	close(sockfd); // Closing connection

	PrintDebugInfoBasedOnVerbosityLevel("Reading answers...", Without_Variable, 0);
	ReadBufferResponseCode(buf, user_to_check, email_site);
}

// We want to check ONLY response code, and if IP was blocked
int ReadBufferResponseCode(char* buf, char* user, char* email)
{
	unsigned int response_code_end_position = 0;
	unsigned int response_code_length = 3;
	unsigned int buf_size = strlen((char*)buf);
	unsigned int pos, j = 0;
	int possible_end = 0;
	int success = 0;
	int line_number = 1; // Where we start
	char response_code[response_code_length]; // Response code consists of three numbers
	char line[buf_size];
	char* p;

	for(pos = 0; pos < buf_size; pos++)
	{
		p = &buf[pos];
		line[pos] = *p;
		if(line_number == 4) // We want to check response code located on line 4 in buffer 
		{
			if(pos < response_code_end_position) // We are on line num 4, now read 3 numbers
			{
				if(isdigit(line[pos]))
				{
					response_code[j] = line[pos];
					j++;

					if(pos == response_code_end_position - END) // Is buffer filled with 3 numbers?
					{
						response_code[j] = '\0';
						CheckResponseCode(response_code, user, email);
						success = 1;
					}		
				}
				else // Not a digit
				{
					printf("\n\033[1;31mBad response code, or not detected... try verbose(2) for more info.\033[0m\n\n");
					break;
				}
			}
		}

		if(line[pos] == '\r' || possible_end == END) // In telnet query each line is ended with \r\n according to standarts
		{
			if(line[pos] == '\n' && possible_end == END) // We cannot check \n immediatelly after \r, so we are using variable
			{
				possible_end = 0;
				line_number++;
				if(line_number == 4)
				{
					response_code_end_position = pos + response_code_length + END; // We got line num 4, let's save position + code length
				}
			}
			else
			{
				if(possible_end == END) // If no \n detected after \r, reset position
				{
					possible_end = 0;
				}
				else
				{
					possible_end = END;
				}
			}
		}
	}
	if(!success) // Check if server says, that IP is blocked
	{
		unsigned int pos, j = 0;
		char text[] = "blocked"; // Word to search in response
		size_t text_size = strlen(text);
		char text_storage[text_size];

		for(pos = 0; pos < buf_size; pos++)
		{
			p = &buf[pos];
			if(isalpha(*p)) // If is character
			{
				text_storage[j] = *p;
				if(strlen(text_storage) >= text_size) // Buffer is filled with some word with same length
				{
					text_storage[text_size] = '\0';
					if(strcmp(text, text_storage) == 0) // If it's a word we are searching for
					{
						printf("\n\033[1;31mServer detected that your IP address is blocked by Spamhaus, it will not give info about mail existence.\033[0m\n\n");
						return 0;
					}
					else
					{
						memset(text_storage, 0, text_size); // Just wrong word with same or bigger length, reset buffer
					}

					j = 0;
				}

				j++;
			}
			else
			{
				j = 0;
				memset(text_storage, 0, text_size); // Whitespace or digit detected, reset buffer
			}
		}
	}

	return 0;
}

// Check server response code and print conclusion
void CheckResponseCode(char* code, char* user, char* site) 
{
	if(strcmp("553", code) == 0)
	{
		printf("\n\033[1;31mThe mail %s is not a valid RFC-5321 address, PLEASE USE ONLY USERNAME, and with valid characters!\033[0m\n\n", site);
		exit(1);
	}
	else if(strcmp("550", code) == 0)
	{
		printf("\n\033[0;31mUser account %s does not exist on %s\033[0m\n\n", user, site);
	}
	else if(strcmp("250", code) == 0)
	{
		printf("\n\033[1;32mUser %s exists on %s!\033[0m\n\n", user, site);
	}
	else if(strcmp("501", code) == 0)
	{
		printf("\n\033[1;31mInvalid argument in query, something went wrong, try to use verbose(2).\033[0m\n\n");
	}
	else if(strcmp("221", code) == 0)
	{
		printf("Server closed connection\n");
	}
	else 
	{
		printf("\n\033[0;31mUnknown response code %s.\033[0m\n\n", code);
	}
}

// For each mail in file execute core logic
void ReadMailsFromFileAndExecuteCoreLogic(FILE* fp, char* user_to_check)
{
	size_t line_length = 254;
	char* email_site;
	if((email_site = (char*)malloc(line_length)) == NULL)
	{
		perror("Error allocating space:");
	}

	while((getline(&email_site, &line_length, fp)) != -1)
	{
		if(isspace(*email_site))
		{
			continue;
		}
		else if(strlen(email_site) > line_length)
		{
			printf("File line is bigger than 254 chars\n");
			exit(1);
		}

		email_site[strlen(email_site) - 1] = '\0';
		CoreLogic(user_to_check, (unsigned char*)email_site);
	}

	printf("End of file\n");
	free(email_site);
}

// Logic with all core steps, one by one 
// Consists of Getting MX record from DNS, then A record by MX, then telnet by A (IPv4) record
// No need to hardcode DNS servers/email servers/IPv4 records
void CoreLogic(char* user_to_check, unsigned char* email_site)
{
	char dns_saved_email_server[50];
	unsigned char* dns_response_email_server = NULL;

	// Get MX record from DNS and save it
	if(strlen((char*)(dns_response_email_server = GetDnsInfo(email_site, MX))) != 0) // If not empty answer
	{
		strncpy(dns_saved_email_server, (char*)dns_response_email_server, sizeof(dns_saved_email_server));

		// Get A record (IPv4) of MX record response (reverse lookup)
		char* destination_ip = (char*)GetDnsInfo(dns_response_email_server, A);

		// Let's talk to server with information we got
		// StartTelnet(destination_ip, user_to_check, (unsigned char*)dns_saved_email_server, (char*)email_site);
	}
	else
	{
		printf("Got bad response, MX record not found");
	}
}

// To get rid of many IF's in code which are checking verbosity level
// Prints message based on verbosity level that user chose
void PrintDebugInfoBasedOnVerbosityLevel(const char* message, char* variable_to_print, unsigned int level)
{		
	if(VERBOSITY_LEVEL >= level)
	{
		printf("%s%s\n", message, variable_to_print);
	}
}