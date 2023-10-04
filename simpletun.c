#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>
// #include <bits/ioctls.h>
// #include <bits/ioctl-types.h>
// #include <sys/ttydefaults.h>
#include <netinet/ip6.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

int debug;
char *progname;
// ------------------- ip head parse -----------------
/*
60 00 00 00 00 08 3A FF  FE 80 00 00 00 00 00 00  |  `.....:.........
84 16 F9 EF 98 C3 62 C0  FF 02 00 00 00 00 00 00  |  ......b.........
00 00 00 00 00 00 00 02  85 00 03 AD 00 00 00 00  |  ................

       0                1                2                3
       0 1 2 3 4 5 6 7  8 9 0 1 2 3 4 5 6 7  8 9 0 1 2 3 4 5 6 7  8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   0: |Version| Traffic Class |           Flow Label                  |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   4: |         Payload Length        |  Next Header  |   Hop Limit    |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   8: |                                                               |
      .                                                               .
      .                         Source Address                        .
      .                                                               .
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  24: |                                                               |
      .                                                               .
      .                      Destination Address                      .
      .                                                               .
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

void print_ipv6_header(char *buf) {

    struct ip6_hdr *ip6h = (struct ip6_hdr *)buf;
    printf("IPv6 Header:\n");
    printf("   |-Version     : %u\n", ip6h->ip6_vfc >> 4);
    printf("   |-Traffic Class: 0x%02x\n", ip6h->ip6_flow & 0x0ff00000);
    printf("   |-Flow Label  : 0x%05x\n", ip6h->ip6_flow & 0x000fffff);
    printf("   |-Payload Length : %u\n", ntohs(ip6h->ip6_plen));
    printf("   |-Next Header : %u\n", ip6h->ip6_nxt);
    printf("   |-Hop Limit   : %u\n", ip6h->ip6_hops);

    struct in6_addr src, dst;
    memcpy(&src, &(ip6h->ip6_src), sizeof(struct in6_addr));
    memcpy(&dst, &(ip6h->ip6_dst), sizeof(struct in6_addr));

    char src_addr[INET6_ADDRSTRLEN];
    char dst_addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &src, src_addr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &dst, dst_addr, INET6_ADDRSTRLEN);

    printf("   |-Source IPv6: %s\n", src_addr);
    printf("   |-Dest IPv6  : %s\n", dst_addr);

}
// ---------------------------------------------------

void hexdump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        dprintf(2, "%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' &&
            ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            dprintf(2, " ");
            if ((i + 1) % 16 == 0) {
                dprintf(2, "|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    dprintf(2, " ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    dprintf(2, "   ");
                }
                dprintf(2, "|  %s \n", ascii);
            }
        }
    }
}


/// @brief allocates or reconnects to a tun/tap device. The caller must reserve enough space in *dev. 
///        通过打开tun的fd申请一个ifreq的结构体 用ioctl创建一个tun的虚拟网卡
/// @param dev 
/// @param flags 
/// @return 
int tun_alloc(char *dev, int flags) {

    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if( (fd = open(clonedev , O_RDWR)) < 0 ) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    // Tunnel Set Interface: 用tun的fd去设置一个ifreq结构体
    if((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    // printf("[+] new ifr.ifr_name is %s\n", ifr.ifr_name);
    strcpy(dev, ifr.ifr_name);// 这里似乎没什么必要 因为传入的就是我们-i指定的参数

    return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/

/// @brief read routine that checks for errors and exits if an error is returned. 
/// @param fd 
/// @param buf 
/// @param n 
/// @return 
int cread(int fd, char *buf, int n){
  
    int nread;

    if((nread = read(fd, buf, n)) < 0){
        perror("Reading data");
        exit(1);
    }
    return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){

    if(n == 0) return 0;// TODO:
  
    int nwrite;

    if((nwrite = write(fd, buf, n)) < 0){
        perror("Writing data");
        printf("[-] fd = %d, buf at %p, n = %d\n", fd, buf, n);
        exit(1);
    }
    return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug) {
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  
    int tap_fd, option;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    int maxfd;
    uint16_t nread, nwrite, plength;
    char buffer[BUFSIZE];
    struct sockaddr_in local, remote;
    char remote_ip[16] = "";            /* dotted quad IP string */
    unsigned short int port = PORT;
    int sock_fd, net_fd, optval = 1;
    socklen_t remotelen;
    int cliserv = -1;    /* must be specified on cmd line */
    unsigned long int tap2net = 0, net2tap = 0;

    progname = argv[0];
  
    /* Check command line options */
    while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0) {
        switch(option) {
        case 'd':
            debug = 1;
            break;
        case 'h':
            usage();
            break;
        case 'i':
            strncpy(if_name,optarg, IFNAMSIZ-1);// interface
            break;
        case 's':// run in server mode
            cliserv = SERVER;
            break;
        case 'c':// run in client mode and specify server's address
            cliserv = CLIENT;
            strncpy(remote_ip,optarg,15);
            break;
        case 'p':// port
            port = atoi(optarg);
            break;
        case 'u':// tun mode
            flags = IFF_TUN;
            break;
        case 'a':// tap mode
            flags = IFF_TAP;
            break;
        default:
            my_err("Unknown option %c\n", option);
            usage();
        }
    }

    argv += optind;
    argc -= optind;

    if(argc > 0) {
        my_err("Too many options!\n");
        usage();
    }

    if(*if_name == '\0') {
        my_err("Must specify interface name!\n");
        usage();
    } else if(cliserv < 0) {
        my_err("Must specify client or server mode!\n");
        usage();
    } else if((cliserv == CLIENT) && (*remote_ip == '\0')) {
        my_err("Must specify server address!\n");
        usage();
    }

    /* initialize tun/tap interface */
    // IFF_NO_PI: Do not provide packet information 不包含以太网头部
    // 不设置IFF_NO_PI，会在报文开始处添加4个额外的字节(2字节的标识和2字节的协议
    if((tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0) {
        my_err("Error connecting to tun/tap interface %s!\n", if_name);
        exit(1);
    }

    printf("[+] Successfully connected to interface %s\n", if_name);

    // TCP : SOCK_STREAM
    if((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        exit(1);
    }

    if(cliserv == CLIENT) {
        /* Client, try to connect to server */

        /* assign the destination address */
        memset(&remote, 0, sizeof(remote));
        remote.sin_family      = AF_INET;
        remote.sin_addr.s_addr = inet_addr(remote_ip);
        remote.sin_port        = htons(port);

        /* connection request */
        if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0) {
            perror("connect()");
            exit(1);
        }

        net_fd = sock_fd;
        // inet_ntoa 网络字节序列转换成string
        printf("[+] CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));
        
    } else {
        /* Server, wait for connections */

        /* avoid EADDRINUSE error on bind() */
        if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
            perror("setsockopt()");
            exit(1);
        }
        
        memset(&local, 0, sizeof(local));
        local.sin_family      = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port        = htons(port);

        if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0) {
            perror("bind()");
            exit(1);
        }
        
        if (listen(sock_fd, 5) < 0) {
            perror("listen()");
            exit(1);
        }
        
        /* wait for connection request */
        remotelen = sizeof(remote);
        memset(&remote, 0, remotelen);
        if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0) {
            perror("accept()");
            exit(1);
        }

        printf("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));
    }
    
    sleep(3);
    /* use select() to handle two descriptors at once */
    maxfd = (tap_fd > net_fd) ? tap_fd : net_fd;

    while(1) {
        int ret;
        fd_set rd_set;

        FD_ZERO(&rd_set);
        FD_SET(tap_fd, &rd_set); 
        FD_SET(net_fd, &rd_set);
        /*
            监听多个套接字的 I/O 事件
            第一个参数固定为最大文件描述符+1
            rd_set: 可读事件的fd集合

            rd_set集合将被操作系统修改，只会留下就绪的文件描述符，其他文件描述符则会被清除
        */
        ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

        if (ret < 0 && errno == EINTR){
            continue;
        }

        if (ret < 0) {
            perror("select()");
            exit(1);
        }
        // 报文格式的加解密都是在 net <-> tun 之间的

        // rd_set只有tun就绪了 说明是app消息到了tun 处理后转发给net(代表真实网卡)
        if(FD_ISSET(tap_fd, &rd_set)) {
            /* data from tun/tap: just read it and write it to the network */
            
            nread = cread(tap_fd, buffer, BUFSIZE);

            tap2net++;
            printf("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

            /* write length + packet */
            plength = htons(nread);
            nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
            printf("[+] write plength\n");
            nwrite = cwrite(net_fd, buffer, nread);
            print_ipv6_header(buffer);
            printf("[+] write buffer\n");

            printf("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
        }

        // rd_set只有net就绪了 说明是外部消息来了 处理后转发给tun0
        if(FD_ISSET(net_fd, &rd_set)) {
            /* data from the network: read it, and write it to the tun/tap interface. 
            * We need to read the length first, and then the packet */

            /* Read length */
            nread = read_n(net_fd, (char *)&plength, sizeof(plength));
            if(nread == 0) {
                /* ctrl-c at the other end */
                break;
            }

            net2tap++;

            /* read packet */
            nread = read_n(net_fd, buffer, ntohs(plength));
            printf("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

            /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
            hexdump(buffer, nread);
            nwrite = cwrite(tap_fd, buffer, nread);
            printf("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
        }
    }
    
    return 0;
}
