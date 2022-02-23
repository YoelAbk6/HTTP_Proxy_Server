#define _GNU_SOURCE //for strcasestr
#include<stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "threadpool.h"

#define IPV4_LENGTH 32
#define BUF_LEN 512

enum stat_code {
    bad_requestC = 400, forbiddenC = 403, not_foundC = 404, inter_serv_errC = 500, not_supportedC = 501
};

//A linked list of subnetworks
typedef struct IP_list{
    struct in_addr address; //The IP address, already masked
    uint32_t x; //guarantee a 32 bit int in every processor, the subnet mask
    struct IP_list *next;
}IP_list;

//A linked lists of host names
typedef struct host_list{
    char* host_name;
    struct host_list* next;
}host_list;

//Used for passing parameters to void* function
struct arg{
    IP_list *IP_head;
    host_list *host_head;
    int sd;
};

/**
 * Converts the subnet to an IP_list struct and adds it to the list
 * @param subnet The subnet String
 * @param IP_head The list head
 * @param prev_IP The last added IP to the list
 */
void add_IP_to_list(char *subnet, IP_list **IP_head, IP_list **prev_IP){
    IP_list *curr_IP;
    char *token;
    curr_IP = calloc(1, sizeof (IP_list));
    if(!curr_IP){
        fprintf(stderr, "error: calloc\n");
        exit(EXIT_FAILURE);
    }
    token = strtok(subnet, "/");
    inet_aton(token, &curr_IP->address);//convert IP from IPv4 numbers-and-dots into binary form
    curr_IP->address.s_addr = htonl(curr_IP->address.s_addr); //converts from network order, to host order
    unsigned long mask  = strtol(strtok(NULL, "/"), NULL, 10);
    curr_IP->x = 0; //mask to 0
    for(unsigned long i=IPV4_LENGTH - mask; i<IPV4_LENGTH; i++)
        curr_IP->x |= (1U << i); //Sets the ith bit of the mask
    curr_IP->next = NULL;
    curr_IP->address.s_addr &= curr_IP->x; //Mask the IP
    if(!(*prev_IP)){
        *IP_head = curr_IP;
        *prev_IP = curr_IP;
    }
    else{
        (*prev_IP)->next = curr_IP;
        *prev_IP = curr_IP;
    }
}

/**
 * Saves the host within a host_list struct and adds it to the list
 * @param host A string host
 * @param host_head The list head
 * @param prev_host The last host added to the list
 */
void add_host_to_list(char *host, host_list **host_head, host_list **prev_host){
    host_list *curr_host = calloc(1, sizeof (host_list));
    if(!curr_host){
        fprintf(stderr, "error: calloc\n");
        exit(EXIT_FAILURE);
    }
    curr_host->host_name = calloc(strlen(host), 1);
    if(!curr_host->host_name){
        fprintf(stderr, "error: calloc\n");
        exit(EXIT_FAILURE);
    }
    char *token = strtok(host, "\r\n");
    strncpy(curr_host->host_name, token, strlen(host));
    curr_host->next = NULL;
    if(!(*prev_host)){
        *host_head = curr_host;
        *prev_host = curr_host;
    }
    else{
        (*prev_host)->next = curr_host;
        *prev_host = curr_host;
    }
}


/**
 * Converts the string represented IP to binary and compares it to the IPs in the list, masked
 * @param IP_head The IP filter list head
 * @param IP The IP that we want to compare
 * @return returns 1 if there's a matching IP, 0 otherwise
 */
int compare_IPs(IP_list *IP_head, char* IP){
    IP_list IP_to_cmp, *curr_IP = IP_head;
    while(curr_IP){
        inet_aton(IP, &IP_to_cmp.address); //convert IP from IPv4 numbers-and-dots into binary form
        IP_to_cmp.address.s_addr = htonl(IP_to_cmp.address.s_addr); //converts from network order, to host order
        IP_to_cmp.address.s_addr &= curr_IP->x; //Mask IP
        if(!((IP_to_cmp.address.s_addr)^(curr_IP->address.s_addr)))//XOR IPs
            return 1;
        curr_IP = curr_IP->next;
    }
    return 0;
}

/**
 *Compares the host name to the host name in the filter file, and then call compare_IPs
 * @param host_head
 * @param host_name
 * @return 1 if there's a matching, 0 if not, -1 on failure
 */
int compare_Host_names(host_list *host_head, IP_list *IP_head, char *host_name){
    host_list *curr_name = host_head;
    while(curr_name){
        if(!strcasecmp(curr_name->host_name, host_name))
            return 1;
        curr_name = curr_name->next;
    }
    struct hostent *hp;
    hp = gethostbyname(host_name);
    if (!hp) {
        herror("gethostbyname\n");
        return -1;
    }
    return compare_IPs(IP_head,inet_ntoa(*((struct in_addr *)(hp->h_addr))));
}

/**
 * Adds the filter file arguments to an IP list and an Host list
 * @param path The file path
 * @param IP_head The IP list head
 * @param host_head The Host list head
 */
void analyze_filter(const char* path, IP_list **IP_head, host_list **host_head){
    FILE *fp = fopen(path, "r");
    if(!fp){
        perror("error: <fopen>\n");
        exit(EXIT_FAILURE);
    }
    char* line = NULL;
    size_t len = 0;
    IP_list *prev_IP = NULL;
    host_list *prev_host = NULL;
    while(getline(&line, &len, fp) != -1){
       if(isdigit(line[0]))
           add_IP_to_list(line, IP_head, &prev_IP);
       else
           add_host_to_list(line, host_head, &prev_host);
    }
    free(line);
    fclose(fp);
}

/**
 * Receives a status code and returns a corresponding error response
 * @param code The error code number
 */
char* handle_errors(int stat_code) {
    char *stat_text, *stat_msg;
    char *content = "<HTML><HEAD><TITLE></TITLE></HEAD>\r\n<BODY><H4></H4>\r\n\r\n</BODY></HTML>\r\n";
    char error[500];
    unsigned long content_len = strlen(content);
    switch (stat_code) {
        case bad_requestC:
            stat_text = "400 Bad Request";
            stat_msg = "Bad Request.";
            break;
        case forbiddenC:
            stat_text = "403 Forbidden";
            stat_msg = "Access denied.";
            break;
        case not_foundC:
            stat_text = "404 Not Found";
            stat_msg = "File not found.";
            break;
        case inter_serv_errC:
            stat_text = "500 Internal Server Error";
            stat_msg = "Some server side error.";
            break;
        case not_supportedC:
            stat_text = "501 Not supported";
            stat_msg = "Method is not supported.";
            break;
        default:
            stat_text = "unknown error";
            stat_msg = "unknown error\r\n";
    }
    content_len += strlen(stat_text) * 2  + strlen(stat_msg);

    snprintf(error, 500, "HTTP/1.0 %s\r\nContent-Type: text/html\r\nContent-Length: %ld\r\nConnection: close"
                         "\r\n\r\n<HTML><HEAD><TITLE>%s</TITLE></HEAD>\r\n<BODY><H4>%s</H4>\r\n%s\r\n</BODY></HTML>\r\n",
             stat_text, content_len, stat_text, stat_text, stat_msg);

    char * ret_val = malloc(strlen(error) + 1);
    if(!ret_val) {
        perror("error: malloc\n");
        return NULL;
    }
    strcpy(ret_val, error);
    return ret_val;
}


/**
 * Prepare a server to accept clients - creates socket, binds to 'port' and use listen to mark the socket as a passive
 * socket, that will be used to accept incoming connection requests.
 * @param port The server will listen on this port
 * @return The new sd on success, -1 on any syscall failure
 */
int prepare_server(long port){
    int sd;
    struct sockaddr_in srv;
    if ((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("error: socket\n");
        return -1;
    }
    srv.sin_family = AF_INET;
    srv.sin_port = htons(port);
    srv.sin_addr.s_addr = htonl(INADDR_ANY); //Let the client connect to any of the server addresses
    if(bind(sd, (struct sockaddr*)&srv, sizeof (srv)) < 0) {
        perror("error: bind\n");
        return -1;
    }
    if(listen(sd, 5) < 0){
        perror("error: listen\n");
        return -1;
    }
    return sd;
}

/**
 * Writes msg to sd
 * @param sd socket descriptor
 * @param msg msg to be writen
 * @return 1 on success, inter_serv_errC failure
 */
int write_loop(int sd, unsigned char *msg, unsigned long msg_len){
    long n_bytes, sent = 0;
    do {
        n_bytes = write(sd, msg, msg_len - sent);
        if(n_bytes < 0){
            perror("error: write\n");
            return inter_serv_errC;
        }
        sent += n_bytes;
    }while(sent < (long)msg_len);
    return 1;
}


/**
 * Reads the request from the socket
 * @param sd The socket descriptor
 * @param request will hold the request
 * @return total read size on successes, -1 on failure
 */
long read_header(int sd, unsigned char **request, int *err_num){
    int buf_size = BUF_LEN;
    ssize_t tot_read = 0, curr_read_len;
    unsigned char *buf = calloc(buf_size+1, 1), *tmp_ptr = NULL;
    if(!buf){
        fprintf(stderr, "error: calloc\n");
        *err_num = inter_serv_errC;
        return -1;
    }
    while((curr_read_len = read(sd, buf+tot_read, buf_size-tot_read))){
        if(curr_read_len == -1) {
            perror("error: read\n");
            *err_num = inter_serv_errC;
            return -1;
        }
        tot_read += curr_read_len;
        if(!strstr((char*)buf, "\r\n\r\n")){
            buf_size *= 2;
            tmp_ptr = realloc(buf, buf_size + tot_read + 1);
            if(tmp_ptr) {
                buf = tmp_ptr;
                memset(buf + tot_read, '\0', buf_size - tot_read + 1);
            }
            else {
                fprintf(stderr, "error: realloc\n");
                *err_num = inter_serv_errC;
                return -1;
            }
        }
        else{
            buf[buf_size] = '\0';
            *request = buf;
            return tot_read;
        }
    }
    buf[buf_size] = '\0';
    *request = buf;
    return tot_read;
}

/**
 * Validate that the request line contains a method token, a path token and a HTTP/1.X token
 * @param request The HTTP request
 * @param method Will hold the method token
 * @param path Will hold the path token
 * @param protocol Will hold the protocol token
 * @return 1 if valid, 'bad_request' if not
 */
int validate_request_line(char* request, char **method, char **path, char **protocol, char **host){
    char *token = NULL, *host_ptr;
    token = strtok(request, " ");
    if(!token)
        return bad_requestC;
    (*method) = malloc(strlen(token)+1);
    if(!(*method)){
        fprintf(stderr, "error: malloc\n");
        return inter_serv_errC;
    }
    strcpy(*method, token);
    token = strtok(NULL, " ");
    if(!token)
        return bad_requestC;
    (*path) = malloc(strlen(token)+1);
    if(!(*path)){
        fprintf(stderr, "error: malloc\n");
        return inter_serv_errC;
    }
    strcpy(*path, token);
    token = strtok(NULL, " \r\n");
    if(!token)
        return bad_requestC;
    if(!strcasestr(token, "HTTP/1.0") && !strcasestr(token, "HTTP/1.1"))
        return bad_requestC;
    (*protocol) = malloc(strlen(token)+1);
    if(!(*protocol)){
        fprintf(stderr, "error: malloc\n");
        return inter_serv_errC;
    }
    strcpy(*protocol, token);
    token += strlen("HTTP/1.X") +1;
    for(; *token == ' '; token++);
    if(!(host_ptr = strcasestr(token, "Host:")))
        return bad_requestC;
    token = strtok(host_ptr, ": ");
    token  = strtok(NULL, " \r");
    (*host) = malloc(strlen(token)+1);
    if(!(*host)){
        fprintf(stderr, "error: malloc\n");
        return inter_serv_errC;
    }
    strcpy(*host, token);
    return 1;
}
/**
 * Validate that the request is a GET request, with a valid IP that is also not in the filter list
 * @param method The request method
 * @param hp Will hold the hostent struct returned by gethostby
 * @param tmp Struct arg holding the IP and host lists heads
 * @return 1 if valid, corresponding err number if not
 */
int validate_request(char *method, char *host, struct hostent **hp, struct arg tmp){
    int err_num;
    struct in_addr ip;
    if(strcmp(method, "GET") != 0)
        return not_supportedC;
    if(isalpha(host[0])) {
        if (!(*hp = gethostbyname(host))) {
            return not_foundC;
        }
        if((err_num = compare_Host_names(tmp.host_head, tmp.IP_head, host))){
            if(err_num == -1)
                return inter_serv_errC;
            else
                return forbiddenC;
        }
    }
    else{
        inet_aton(host, &ip);
        if (!(*hp = gethostbyaddr(&ip, sizeof(ip), AF_INET ))) {
            return not_foundC;
        }
        if(compare_IPs(tmp.IP_head, host))
            return forbiddenC;
    }
    return 1;
}


/**
 * builds the full path, including the 'index.html'
 * @param path
 * @param host
 * @param full_path
 * @return 1 on success, inter_serv_errC on failure
 */
int build_full_path(char *path, char *host, char **full_path){
    if(path[strlen(path)-1] == '/')
        (*full_path) = calloc(strlen(path) + strlen(host) + strlen("index.html") +1, 1);
    else
        (*full_path) = calloc(strlen(path) + strlen(host) + 1, 1);
    if(!(*full_path)){
        fprintf(stderr, "error: calloc\n");
        return inter_serv_errC;
    }
    sprintf((*full_path), "%s%s", host, path);
    if(path[strlen(path)-1] == '/') {
        char *tmp = "index.html\0";
        strncat((*full_path), tmp, strlen(tmp));
    }
    return 1;
}


/**
 * @param name The file name
 * @return The file mime type
 */
char *get_mime_type(char *name){
    char *ext = strrchr(name, '.');
    if (!ext) return NULL;
    if (strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) return "text/html";
    if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(ext, ".gif") == 0) return "image/gif";
    if (strcmp(ext, ".png") == 0) return "image/png";
    if (strcmp(ext, ".css") == 0) return "text/css";
    if (strcmp(ext, ".au") == 0) return "audio/basic";
    if (strcmp(ext, ".wav") == 0) return "audio/wav";
    if (strcmp(ext, ".avi") == 0) return "video/x-msvideo";
    if (strcmp(ext, ".mpeg") == 0 || strcmp(ext, ".mpg") == 0) return "video/mpeg";
    if (strcmp(ext, ".mp3") == 0) return "audio/mpeg";
    if (strcmp(ext, ".mp4") == 0) return "video/mpeg";
    return "";
}


/**
 * Reads from fp and write to sd
 * @param fp File pointer
 * @param file_size The size to write
 * @param sd Socket descriptor
 * @return 1 on succses, '-1' on failure
 */
int read_fp_write_sd(FILE *fp, long file_size, int sd){
    unsigned long n_bytes = 0, sent;
    unsigned char* buf = calloc(file_size, 1);
    if(!buf){
        fprintf(stderr, "error: calloc\n");
        return inter_serv_errC;
    }
    while(n_bytes < (unsigned long)file_size) {
        sent = fread(buf, 1, file_size, fp);
        n_bytes += sent;
        if (ferror(fp)) {
            fprintf(stderr, "error: fread\n");
            return inter_serv_errC;
        }
       if(write_loop(sd, buf, sent) != 1)
           return inter_serv_errC;
    }
    free(buf);
    return 1;
}


/**
* Receives a path that ends with a file, creates all the folders and the file
* @param full_path
* @return the new file descriptor, '-1' on failure
*/
int create_file_under_path(char *full_path) {
    int fd;
    unsigned long path_len = strlen(full_path);
    char *curr_path = calloc(path_len + 1, 1);
    if(!curr_path)
        return -1;
    char *token = strtok(full_path, "/");
    strncpy(curr_path, token, path_len);
    while (token) {
        if (path_len == strlen(curr_path)) {
            break;
        }
        if (access(curr_path, F_OK) != 0) {//The folder doesn't exist
            if (mkdir(curr_path, S_IRWXU | S_IRWXG | S_IRWXO) == -1) {
                perror("mkdir failed\n");
                return -1;
            }
        }
        token = strtok(NULL, "/");
        strcat(curr_path, "/");
        strncat(curr_path, token, strlen(token));
    }
    if ((fd = open(curr_path, O_CREAT | O_WRONLY, 0700)) == -1) {
        perror("failed to open file\n");
        return -1;
    }
    free(curr_path);
    return fd;
}

/**
 * gets the header, check if the status is 2xx
 * @param header - the http server header
 * @return true(1) if succeeded, false(0) if not
 */
int successful_response(unsigned char *header) {
    char *ptr = strstr((char *) header, "HTTP/1.");
    if (ptr) {
        int status = (int) strtol((ptr + strlen("HTTP/1.x")), NULL, 10);
        return (200 <= status && status <= 299) ? 1 : 0;
    } else
        return 0;
}

/**
 *Handles the HTTP server response - reads it, writes the whole response to the socket and saves the body within a new
 * folder
 * @param from The server socket
 * @param to The client socket
 * @param full_path The file full path
 * @return 1 on success, corresponding err_num on failure
 */
int handle_HTTP_response(int from, int to, char* full_path){
    long buf_size = BUF_LEN, n_bytes, tot_size, header_size;
    unsigned char *buf, *body_ptr;
    int fd = 0, err_num = 0;
    tot_size = read_header(from, &buf, &err_num);
    if(err_num)
        return inter_serv_errC;
    body_ptr = (unsigned char*)strstr((char*)buf, "\r\n\r\n");
    if(!body_ptr)
        return inter_serv_errC;
    body_ptr += 4;
    header_size = body_ptr - buf;
    if(write_loop(to, buf, header_size) != 1)
        return inter_serv_errC;
    if(successful_response(buf)){
        if((fd = create_file_under_path(full_path)) < 0)
            return inter_serv_errC;
        if(write_loop(fd, body_ptr, tot_size - header_size) != 1)
            return inter_serv_errC;
    }
    if(write_loop(to, body_ptr, tot_size - header_size) != 1) {
        free(buf);
        return inter_serv_errC;
    }
    buf_size = tot_size;
    memset(buf, 0, buf_size);
    while((n_bytes = read(from, buf, buf_size))){
        if(n_bytes < 0){
            perror("error: read\n");
            free(buf);
            return inter_serv_errC;
        }
        tot_size += n_bytes;
        if(write_loop(to, buf, n_bytes) != 1) {
            free(buf);
            return inter_serv_errC;
        }
        if(fd > 0) {
            if (write_loop(fd, buf, n_bytes) != 1) {
                free(buf);
                return inter_serv_errC;
            }
        }
        memset(buf, 0, n_bytes);
    }
    close(from);
    free(buf);
    if(fd > 0)
        close(fd);
    printf("File is given from origin server\n");
    printf("\n Total response bytes: %ld\n", tot_size);
    return 1;
}

/**
 * Handles the case in which the file is found locally - Construct response and sends it to the client
 * @param fp The requested file file descriptor
 * @param sd The socket descriptor
 * @param file_name
 * @return 1 on success, 'inter_serv_errC' on failure
 */
int file_is_given_from_local(FILE *fp, int sd, char *file_name){
    long content_length;
    char content_length_length[20] = {0};
    char *mime_type = get_mime_type(file_name), *response;

    if(fseek(fp, 0, SEEK_END) < 0)
        return inter_serv_errC;
    content_length = ftell(fp);
    if(fseek(fp, 0, SEEK_SET) < 0)
        return inter_serv_errC;
    sprintf(content_length_length, "%zd", content_length);
    char *format = "HTTP/1.0 200 OK\r\nContent-length: \r\nContent-type: \r\nconnection: close\r\n\r\n";
    response = calloc((strlen(mime_type) + strlen(content_length_length) + strlen(format) +1), 1);
    if(!response)
        return inter_serv_errC;
    sprintf(response, "HTTP/1.0 200 OK\r\nContent-length: %ld\r\nContent-type: %s\r\nConnection: close\r\n\r\n",
           content_length, mime_type);
    printf("File is given from local filesystem\n");
    write_loop(sd, (unsigned char*)response, strlen(response));
    if(read_fp_write_sd(fp, content_length, sd) != 1) {
        return inter_serv_errC;
    }
    printf("\n Total response bytes: %ld\n", strlen(response)+content_length);
    free(response);
    fclose(fp);
    return 1;
}

/**
 * Handles the case in which the file needs to be asked from the server
 * @param sd The clients sd
 * @param request The request
 * @param host The host name
 * @param full_path The file full path
 * @return 1 on success, corresponding err msg on failure
 */
int file_is_given_from_server(int sd, char *request,  char* host, char *full_path){
    int origin_sd;
    struct sockaddr_in srv;
    struct hostent *hp;
    srv.sin_family = AF_INET;
    if ((origin_sd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("error: socket\n");
        return inter_serv_errC;
    }
    if(!(hp = gethostbyname(host))) {
        return inter_serv_errC;
    }
    srv.sin_port = htons(80);
    srv.sin_addr.s_addr = ((struct in_addr *) (hp->h_addr))->s_addr;
    if (connect(origin_sd, (struct sockaddr *) &srv, sizeof(srv)) < 0) {
        perror("error: connect\n");
        return inter_serv_errC;
    }
    if(write_loop(origin_sd, (unsigned char*) request, strlen(request)) != 1)
        return inter_serv_errC;
    if(handle_HTTP_response(origin_sd,sd,full_path) != 1)
        return inter_serv_errC;
    return 1;
}

//Constructs a new request with connection: close in it in order to handle HTTP/1.1 keeps alive
int construct_closed_request(char **request, char *host, char* path, char *protocol){
    char *tmp = "GET  \r\nHost: \r\nConnection: close\r\n\r\n", *ptr;
    ptr = realloc((*request), strlen(tmp) + strlen(host) + strlen(path) + strlen(protocol) + 1);
    if(!ptr) {
        fprintf(stderr, "error: realloc\n");
        return inter_serv_errC;
    }
    (*request) = ptr;
    sprintf((*request), "GET %s %s\r\nHost: %s\r\nConnection: close\r\n\r\n", path, protocol, host);
    return 1;
}

//Frees the tokens
void free_tokens(char *req, char* method, char *path, char *proto, char *host, char *req_cpy, char *err_msg, char* ful_p){
    if(req) free(req);
    if(method) free(method);
    if(path) free(path);
    if(proto) free(proto);
    if(host) free(host);
    if(req_cpy) free(req_cpy);
    if(err_msg) free(err_msg);
    if(ful_p) free(ful_p);
}

/**
 * The negotiation functions acts like the "main" of each thread
 * @param arg holding the socket descriptor, IP list and host list heads
 * @return 1 on successes, '-1' on failure
 */
int negotiation_func(void* arg){
    struct arg tmp = *(struct arg*)arg;
    struct hostent *hp = NULL;
    int sd = tmp.sd, err_num = 0;
    char *request = NULL, *method = NULL, *path = NULL , *protocol = NULL, *host = NULL, *req_cpy = NULL, *err_msg = NULL, *full_path = NULL;
    FILE *fp;
    read_header(tmp.sd, (unsigned char **) &request, &err_num);
    if(err_num){
        err_msg = handle_errors(inter_serv_errC);
        write_loop(sd, (unsigned char*)err_msg, strlen(err_msg));
        free(err_msg);
        close(sd);
        return -1;
    }
    req_cpy = calloc(strlen(request) + 1, 1);

    if(!req_cpy){
        err_msg = handle_errors(inter_serv_errC);
        write_loop(sd, (unsigned char*)err_msg, strlen(err_msg));
        free(request);
        free(err_msg);
        close(sd);
        return -1;
    }
    strncpy(req_cpy, request, strlen(request));
    if(((err_num = validate_request_line(req_cpy, &method, &path, &protocol, &host)) != 1)){
        err_msg = handle_errors(err_num);
        write_loop(sd, (unsigned char*)err_msg, strlen(err_msg));
        free_tokens(request, method, path, protocol, host, req_cpy, err_msg, full_path);
        close(sd);
        return -1;
    }
    if((err_num = validate_request(method, host, &hp, tmp)) != 1){
        err_msg = handle_errors(err_num);
        write_loop(sd, (unsigned char*)err_msg, strlen(err_msg));
        free_tokens(request, method, path, protocol, host, req_cpy, err_msg, full_path);
        close(sd);
        return -1;
    }

    if((err_num = construct_closed_request(&request, host, path, protocol)) != 1){
        err_msg = handle_errors(err_num);
        write_loop(sd, (unsigned char*)err_msg, strlen(err_msg));
        free_tokens(request, method, path, protocol, host, req_cpy, err_msg, full_path);
        close(sd);
        return -1;
    }
    printf("HTTP request =\n%s\nLEN = %lu\n", request, strlen(request));
    if((err_num = build_full_path(path, host, &full_path)) != 1){
        err_msg = handle_errors(err_num);
        write_loop(sd, (unsigned char*)err_msg, strlen(err_msg));
        free_tokens(request, method, path, protocol, host, req_cpy, err_msg, full_path);
        close(sd);
        return -1;
    }
    if((fp = fopen(full_path, "r"))){
        if((err_num = file_is_given_from_local(fp, sd, full_path)) != 1){
            err_msg = handle_errors(err_num);
            write_loop(sd, (unsigned char*)err_msg, strlen(err_msg));
            free_tokens(request, method, path, protocol, host, req_cpy, err_msg, full_path);
            close(sd);
            return -1;
        }
    }
    else{
        if((err_num = file_is_given_from_server(sd, request, host, full_path)) != 1){
            err_msg = handle_errors(err_num);
            write_loop(sd, (unsigned char*)err_msg, strlen(err_msg));
            free_tokens(request, method, path, protocol, host, req_cpy, err_msg, full_path);
            close(sd);
            return -1;
        }
    }
    free_tokens(request, method, path, protocol, host, req_cpy, err_msg, full_path);
    close(sd);
    return 1;
}

//Gets the lists heads and free them
void free_lists(IP_list *IP_head, host_list *host_head){
    IP_list * curr_IP;
    host_list * curr_host;
    while(host_head){
        curr_host = host_head;
        host_head = host_head->next;
        free(curr_host->host_name);
        free(curr_host);
    }
    while(IP_head){
        curr_IP = IP_head;
        IP_head = IP_head->next;
        free(curr_IP);
    }
}

int main(int argc, char *argv[]) {
    IP_list *IP_head = NULL;
    host_list *host_head = NULL;
    int sd;
    char *err_msg;
    long max_n_of_req, i, port, pool_size;

    if(argc != 5){
        printf("Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
        exit(EXIT_FAILURE);
    }

    port = strtol(argv[1], NULL, 10);
    pool_size = strtol(argv[2], NULL, 10);
    max_n_of_req = strtol(argv[3], NULL, 10);

    if(pool_size <=0 || max_n_of_req <= 0 || port <= 0 || pool_size > MAXT_IN_POOL) {
        printf("Usage: proxyServer <port> <pool-size> <max-number-of-request> <filter>\n");
        exit(EXIT_FAILURE);
    }

    threadpool *pool = create_threadpool((int)pool_size);
    if(!pool){
        fprintf(stderr, "create_threadpool failed\n");
        exit(EXIT_FAILURE);
    }

    analyze_filter(argv[4], &IP_head, &host_head);
    if(((sd = prepare_server(port)) < 0)) {
        destroy_threadpool(pool);
        free_lists(IP_head, host_head);
        exit(EXIT_FAILURE);
    }

    struct arg **tmp = malloc(max_n_of_req * sizeof (struct arg*));
    if(!tmp){
        fprintf(stderr, "error: malloc failed\n");
        destroy_threadpool(pool);
        free_lists(IP_head, host_head);
        exit(EXIT_FAILURE);
    }
    for(i = 0; i<max_n_of_req; i++){
        tmp[i] = malloc(sizeof (struct arg));
        if(!tmp[i]){
            fprintf(stderr, "error: malloc\n");
            err_msg = handle_errors(inter_serv_errC);
            write_loop(sd, (unsigned char*)err_msg, strlen(err_msg));
        }
        else{
            tmp[i]->sd = accept(sd, NULL, NULL);
            if (tmp[i]->sd < 0) {
                perror("error: accept\n");
                continue;
            }
            tmp[i]->IP_head = IP_head;
            tmp[i]->host_head = host_head;
            dispatch(pool, negotiation_func, (void *)tmp[i]);
        }
    }
    destroy_threadpool(pool);
    for(i=0; i<max_n_of_req; i++)
        free(tmp[i]);
    free(tmp);
    free_lists(IP_head, host_head);
    close(sd);
    return 0;
}