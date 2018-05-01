#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

struct HTTP_proxy_req_header{
    char* req_line;
    char* full_req_url;
    char* host;
    char* user_agent;
    char* accept;
    char* accept_lang;
    char* accept_encoding;
    char* cookie;
    char* connection;
    char* upgrade_insecure_req;
    char* via;
    char* x_fwd;
};


/* Parse request line into METHOD, URL, VERSION */
char **parsing_req_line(char* req_line){
    char **parsed = (char**)malloc(3*sizeof(char*));
    parsed[0] = (char*)malloc(5*sizeof(char));
    parsed[1] = (char*)malloc(200*sizeof(char));
    parsed[2] = (char*)malloc(11*sizeof(char));
  
    char *start, *end;
    start = req_line;
    end = req_line;
    int i = 0;
    
    while (end != NULL){ //end of line 
        int j = 0;
        if ((end = strchr(start, ' ')) != NULL){
            end++;
        }
        
        /*parsed[0] = METHOD, parsed[1] = URL, parsed[2] = VERSION */
        while((start != end) && (*start != '\0')){
            parsed[i][j] = *start;
            start++; 
            j++; // Proceed to next character in an element
        }
        i++; //Proceed to next element
    }
    if (strcmp(parsed[0], "GET ")){ //deny request except for GET Method
        return NULL;
    }
    return parsed;
}

/*  return relative url extracted from absolute url */ 
char *get_rel_url(char* url){
    if (url){
        char *ptr = url;
        while (*ptr != '\0'){
            if(*ptr == '/' && *(ptr-1) != '/')
                url = ptr;
            ptr++;
        }
    }
    return url;
}



struct HTTP_proxy_req_header *get_req_header(char* buf){
    struct HTTP_proxy_req_header *req_header = malloc(8000);
    char **parsed;
    char* token;
    char* req_line;
    //Fill in request line 
    token = strtok(buf,"\r\n");
    req_line = buf;

    //  modify original request line to proxy version
    parsed = parsing_req_line(req_line);
    
    req_header->full_req_url = parsed[1]; //fill in full request url: http://ee323.kaist.ac.kr/rfc2616.html

    char *rel_url = get_rel_url(parsed[1]); //Relative url: /rfc2616.html
    char *str = malloc(strlen(parsed[0])+strlen(rel_url)+strlen(parsed[2])+1);
    str = strcat(strcat(parsed[0],rel_url),parsed[2]); //concatenate parsed request line
    
    req_header->req_line = str; //fill in request line for proxy
    
    //Deny request other than GET
    if (req_header->req_line == NULL){
        return NULL;
    }

    //Fill in host    
    token = strtok(NULL,"\r\n");
    req_header->host = token;
    
    //Fill in user-agent
    token = strtok(NULL,"\r\n");
    req_header->user_agent = token;

    //Fill in accept
    token = strtok(NULL,"\r\n");
    req_header->accept = token;
    
    //Fill in accept-lang
    token = strtok(NULL,"\r\n");
    req_header->accept_lang = token;
    
    //Fill in accept-encoding
    token = strtok(NULL,"\r\n");
    req_header->accept_encoding = token;
    
    //Fill in connection
    token = strtok(NULL, "\r\n");
    req_header->connection = token;

    //Fill in upgrade-insecure-requests
    token = strtok(NULL, "\r\n\r\n");
    req_header->upgrade_insecure_req = token;
    
    return req_header;
}

void rearrange_header(struct HTTP_proxy_req_header *req_header, char** req_buf){
    //concatenate request line
    *req_buf = strcat(req_header->req_line,"\r\n");
    
    //concatenate user agent
    *req_buf = strcat(*req_buf, req_header->user_agent);
    *req_buf = strcat(*req_buf, "\r\n");

    //concatenate accept
    *req_buf = strcat(*req_buf, req_header->accept);
    *req_buf = strcat(*req_buf, "\r\n");

    //concatenate accept-lang
    *req_buf = strcat(*req_buf, req_header->accept_lang);
    *req_buf = strcat(*req_buf, "\r\n");

    //concatenate accept-encoding
    *req_buf = strcat(*req_buf, req_header->accept_encoding);
    *req_buf = strcat(*req_buf, "\r\n");

    //Cookie
    *req_buf = strcat(*req_buf,"Cookie: _ga=GA1.3.1086174080.1523035245\r\n");

    //concatenate upgrade-insecure-requests
    *req_buf = strcat(*req_buf, req_header->upgrade_insecure_req);
    *req_buf = strcat(*req_buf, "\r\n");

    //concatenate host
    *req_buf = strcat(*req_buf, req_header->host);
    *req_buf = strcat(*req_buf, "\r\n");

    //concatenate via
    *req_buf = strcat(*req_buf, req_header->via);
    *req_buf = strcat(*req_buf, "\r\n");

    //concatenate X-forwarded-for
    *req_buf = strcat(*req_buf, req_header->x_fwd);
    *req_buf = strcat(*req_buf, "\r\n");

    *req_buf = strcat(*req_buf, "Cache-Control: max-age=259200\r\n");

    //concatenate connection
    *req_buf = strcat(*req_buf, req_header->connection);
    *req_buf = strcat(*req_buf, "\r\n\r\n");
}



int main(int argc, char** argv){
    int proxyfd,cli_connfd, serv_connfd; /* a socket descriptor for proxy */
    struct sockaddr_in proxyaddr, cliaddr, servaddr;/* a server, client, proxy address structure */
    struct hostent *h;
    int enable = 1; /* for setsockopt */
    socklen_t len; /* for accept, length of cliaddr */
    char req_buf[8000]; /* request buffer from client (size: 8kB)*/
    char *modified_req_buf; // modified request
    char resp_buf[8000]; /* response buffer from server (size: 8kB) */
    int n_req, n_resp; /* # of bytes read*/
    
    proxyfd = socket(AF_INET, SOCK_STREAM, 0); /* make a socket */
    setsockopt(proxyfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof (int));
    /* make the listening socket *reusable*, otherwise we need to wait 15 minutes */

    bzero(&proxyaddr, sizeof(proxyaddr)); /* clear proxyvaddr */

    proxyaddr.sin_family = AF_INET; /* IPv4 */
    proxyaddr.sin_port = htons(atoi(argv[1])); /* port #: 9999 */
    proxyaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    /*proxy socket will receive any connection request regardless of the IP address */
    
    bind(proxyfd, &proxyaddr, sizeof(proxyaddr)); //bind the servaddr to proxyfd
    
    listen(proxyfd, 8); //waiting incoming connections

    for(; ;){
	    cli_connfd = accept(proxyfd, &cliaddr, &len);
        printf("%d\n",servaddr.sin_addr.s_addr);
	    while((n_req=read(cli_connfd,req_buf,sizeof(req_buf)))>0){ 
            
            char **parsed_req_line;
            char *req_line;
            char *proxy_req_line;
            struct HTTP_proxy_req_header *req_header;
           
            printf("%s",req_buf);
            
            req_header = get_req_header(req_buf); //extract each attribute of header (request line modified)
             
            //create socket for sending request to server
            serv_connfd = socket(AF_INET, SOCK_STREAM, 0); //make a socket for server connection
            
            bzero (&servaddr, sizeof(servaddr)); //initialize servaddr to zero bytes

/*
            h = gethostbyname("ee323.kaist.ac.kr"); //Get IP address of server: ee323.kaist.ac.kr
            
            printf ("Host Name -> %s\n", h->h_name);
            printf ("IP address -> %s\n", inet_ntoa(*(struct in_addr*)h -> h_name));*/
            servaddr.sin_family = AF_INET; //IPv4
            servaddr.sin_port = htons(80); //Web server
            inet_pton(AF_INET,"143.248.36.166", &servaddr.sin_addr.s_addr); //Binary IP address of ee323.kaist.ac.kr        

            /*  MODIFIY HTTP REQUEST */ 
            req_header->via = "Via: 1.1 euigon-HP-ENVY-Sleekbook-4-PC (squid/3.5.12)"; //add attribute 'via'
            req_header->x_fwd = "X-Fowarded-For: 127.0.0.1"; //add attribute 'X-forwarded-for'
            
            rearrange_header(req_header, &modified_req_buf); //rearrange request header to convert into HTTP GET request from proxy
            printf("%s",modified_req_buf);
           
            /*  SEND REQUEST TO SERVER */ 
            if ((connect(serv_connfd, &servaddr, sizeof(servaddr)))==-1){ //connect to the server
                perror("connect");
            }
            
            write(serv_connfd, modified_req_buf, sizeof(modified_req_buf)); //request modified HTTP request to the server
            n_resp = read(serv_connfd, resp_buf, sizeof(resp_buf));
            resp_buf[n_resp] = 0;   
            printf("%s\n", resp_buf);
            free(req_header);
        }
    }
}

