#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<string.h>
#include<mysql/mysql.h>
#include<unistd.h>

MYSQL* conn_ptr;
unsigned int timeout=7;//数据库连接超时时间
#define MAXRECVLEN 65535
char trans[MAXRECVLEN];
void change(int i,char temp[])
{
    int low=i%16;//低位
    int high=i/16;//高位
    if(low<=9)
    {
        temp[1]='0'+low;
    }
    else{
        temp[1]='a'+low-10;
    }
    if(high<=9)
    {
        temp[0]='0'+high;
    }
    else{
        temp[0]='a'+high-10;
    }
}
void processPacket(u_char* arg,const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    //1.连接数据库
    int ret=0;
    conn_ptr=mysql_init(NULL);
    if(!conn_ptr)
    {
        printf("mysql_init failed!\n");
        return;
    }
    ret=mysql_options(conn_ptr,MYSQL_OPT_CONNECT_TIMEOUT,(const char*)&timeout);//设置超时选项
    if(ret)
    {
        printf("options set error\n");
    }
    //连接数据库
    conn_ptr=mysql_real_connect(conn_ptr,"192.168.182.1","zhaotiedan","zss060310","packet",0,NULL,0);
    if(conn_ptr)
    {
        printf("Connection Succeed!\n");
    }
    //2.输出抓到的数据包
    int* count=(int*)arg;
    printf("Packet Count: %d\n", ++(*count));
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("Playload:\n");
    //将数据包以16进制存入trans数组，写入数据库
    int i=0;
    int j=0;
    char temp[2];
    memset(trans,0,MAXRECVLEN);
    for(i=0;i<pkthdr->len;i++)
    {
        change((int)packet[i],temp);//转化为16进制
        trans[j++]=temp[0];
        trans[j++]=temp[1];
        trans[j++]=' ';
        printf("%02x ",packet[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("tranInProcess=%s\n\n",trans);
    char sql_insert[2000];//数据库插入语句数组
    //int t=1;
    sprintf(sql_insert,"insert into packet(id,time,packet) VALUES(1,now(),'%s');",trans);//将trans数组插入数据库
    mysql_query(conn_ptr,sql_insert);
    if(!ret)
    {
        printf("Inserted %lu rows\n",(unsigned long)mysql_affected_rows(conn_ptr));//返回上次UPDATE更改行数
    }
    else{
        printf("Connect Erro:%d %s\n",mysql_errno(conn_ptr),mysql_error(conn_ptr));//返回错误代码、错误消息
    }
}

void GetPacket()
{
    //1.探测可用网卡
    char errbuf[PCAP_ERRBUF_SIZE];//保存错误信息
    char* devstr;//网卡设备名
    pcap_if_t* alldevs;//所有网卡对象指针
    pcap_if_t* d;//目标网卡对象指针，这里是ens33
    if(pcap_findalldevs(&alldevs,errbuf)==-1)
    {
       fprintf(stderr,"Error in pcap_findalldevs_ex:%s\n",errbuf);
       exit(1);
    }
    //搜索设备ens33
    int i=0;
    for(d=alldevs;d!=NULL;d=d->next)
    {
        if(strcmp(d->name,"ens33")==0)
        {
            devstr=d->name;
            printf("success:%d.%s\n",++i,d->name);
            break;
        }
    }
    if(!devstr)
    {
        printf("error:%s\n",errbuf);
        exit(1);
    }

    //2.打开设备，等待数据包到来
    pcap_t* device=pcap_open_live(devstr,65535,1,0,errbuf);//打开探测接口
    if(!device)
    {
        printf("error:pcap_open_live:%s\n",errbuf);
        exit(1);
    }
    //构造一个过滤器
    struct bpf_program filter;
    pcap_compile(device,&filter,"ip",1,0);
    pcap_setfilter(device,&filter);
    //3.开始循环抓取数据包，对每个包循环调用proccessPacket函数
    int count=0;
    pcap_loop(device,3,processPacket,(u_char*)&count);
    //printf("transInGet=%s\n\n",trans);
    pcap_close(device);
    return;
}
int main()
{
    GetPacket(); 
    return 0;
}
