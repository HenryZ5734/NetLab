#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // step1: 数据包长度检测
    if(buf->len < sizeof(ip_hdr_t)){
        return ;
    }

    // step2：报头检测
    ip_hdr_t *pkt = (ip_hdr_t *)buf->data;
    if(
        pkt->version != 4 ||
        pkt->hdr_len > buf->len
    ){
        return ;
    }

    // step3：checksum检测
    uint16_t checksum = pkt->hdr_checksum16;
    pkt->hdr_checksum16 = 0;
    if(checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t)) != checksum){
        return ;
    }
    pkt->hdr_checksum16 = checksum;

    // step4：ip地址检测
    if(memcmp(pkt->dst_ip, net_if_ip, NET_IP_LEN) != 0){
        return ;
    }

    // step5：上层协议检查
    if(!((pkt->protocol == NET_PROTOCOL_UDP) || (pkt->protocol == NET_PROTOCOL_ICMP))){
        icmp_unreachable(buf, pkt->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }

    // step6：去除填充字段
    if(swap16(pkt->total_len16) < buf->len){
        buf_remove_padding(buf, buf->len - swap16(pkt->total_len16));
    }

    // step7：去除ip报头
    buf_remove_header(buf, sizeof(ip_hdr_t));

    // step8：向上层传递数据包
    net_in(buf, pkt->protocol, pkt->src_ip);
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    // step1：添加ip头部
    buf_add_header(buf, sizeof(ip_hdr_t));

    // step2：填写ip头部
    ip_hdr_t *pkt = (ip_hdr_t *)buf->data;
    pkt->hdr_len = sizeof(ip_hdr_t) / IP_HDR_LEN_PER_BYTE;  
    pkt->version = IP_VERSION_4;
    pkt->tos = 0;
    pkt->total_len16 = swap16(buf->len);
    pkt->id16 = swap16(id);
    pkt->flags_fragment16 = swap16((mf == 1)? ((offset >> 3)|IP_MORE_FRAGMENT) : (offset >> 3));
    pkt->ttl = IP_DEFALUT_TTL;
    pkt->protocol = protocol;
    pkt->hdr_checksum16 = 0;
    memcpy(pkt->src_ip,net_if_ip,NET_IP_LEN);
    memcpy(pkt->dst_ip,ip,NET_IP_LEN);

    // step3：计算checksum
    pkt->hdr_checksum16 = checksum16((uint16_t *)pkt, sizeof(ip_hdr_t));

    // step4：发送数据包
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    // 检查是否需要分片
    static int id = 0;
    int pkt_len = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    if(buf->len > pkt_len){
        int cnt = 0;
        uint16_t offset = 0; 
        while((cnt+1) * pkt_len <= buf->len){
            buf_init(&txbuf, pkt_len);
            memcpy(txbuf.data, buf->data+offset, pkt_len);
            ip_fragment_out(&txbuf, ip, protocol, id, offset, 1);
            cnt++;
            offset += pkt_len;
        }

        int remain_len = buf->len - offset;
        if(remain_len > 0){
            buf_init(&txbuf, remain_len);
            memcpy(txbuf.data, buf->data+offset, remain_len);
            ip_fragment_out(&txbuf, ip, protocol, id, offset, 0);
        }
        id++;
    }
    else{
        buf_init(&txbuf, buf->len);
        memcpy(txbuf.data, buf->data, buf->len);
        ip_fragment_out(&txbuf, ip, protocol, id++, (uint16_t)0, 0);
    }
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}