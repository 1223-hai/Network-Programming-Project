#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define SERVER_IP "192.168.161.133"
#define SERVER_PORT 8888 // Đổi sang cổng 8888
#define BUF_SIZE 1024

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    char buffer[BUF_SIZE];
    char domain[256];

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Timeout 5 giây
    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    printf("--- DNS Resolver Client ---\n");
    
    while (1) {
        printf("\nEnter domain to resolve (or 'exit'): ");
        if (scanf("%s", domain) != 1) break; // Thoát an toàn nếu lỗi nhập
        if (strcmp(domain, "exit") == 0) break;

        // Đóng khung thông điệp
        snprintf(buffer, sizeof(buffer), "%s\n", domain);

        // Bắn gói tin
        int sent_bytes = sendto(sockfd, buffer, strlen(buffer), 0, (const struct sockaddr *)&server_addr, sizeof(server_addr));
        if (sent_bytes < 0) {
            perror("\n[LỖI] Không thể gửi gói tin đi");
            continue;
        } else {
            printf("[DEBUG] Đã bắn thành công %d bytes. Đang chờ phản hồi...\n", sent_bytes);
        }

        // Chờ nhận phản hồi
        socklen_t len = sizeof(server_addr);
        int n = recvfrom(sockfd, buffer, BUF_SIZE - 1, 0, (struct sockaddr *)&server_addr, &len);
        
        if (n > 0) {
            buffer[n] = '\0';
            printf("\n%s\n", buffer);
        } else {
            printf("\n[LỖI] Timeout! Server không phản hồi sau 5 giây.\n");
        }
    }
    
    close(sockfd);
    return 0;
}
