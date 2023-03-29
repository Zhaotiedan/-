
#include<iostream>
#include<vector>
#include<string>
#include<bitset>
#include<sstream>
#include <mysql.h> // mysql文件
using namespace std;
#define SQL_MAX 256	// sql语句字符数组最大值

string changeBin(string infor)//16进制字符串转2进制字符串
{
	string res;
	for (int i = 0; i < infor.size(); i++)
	{
		if (infor[i] == ' ')
		{
			continue;
		}
		switch (infor[i])
		{
		case '0': res.append("0000"); 
			break;
		case '1': res.append("0001"); 
			break;
		case '2': res.append("0010"); 
			break;
		case '3': res.append("0011"); 
			break;
		case '4': res.append("0100"); 
			break;
		case '5': res.append("0101"); 
			break;
		case '6': res.append("0110"); 
			break;
		case '7': res.append("0111"); 
			break;
		case '8': res.append("1000"); 
			break;
		case '9': res.append("1001"); 
			break;
		case 'a': res.append("1010"); 
			break;
		case 'b': res.append("1011"); 
			break;
		case 'c': res.append("1100"); 
			break;
		case 'd': res.append("1101"); 
			break;
		case 'e': res.append("1110"); 
			break;
		case 'f': res.append("1111");
			break;
		}
	}
	return res;
}
string changeHex(string infor)//2进制字符串转16进制字符串,保证每次传进来都是4位
{
	string res;
	int temp = 0;
	int x = 0;//2的幂次方
	for (int i = 3; i >= 0; i--)
	{
		temp += (infor[i] - '0') * pow(2, x);
		x++;
	}
	if (temp >= 0 && temp <= 9)
	{
		res = temp + '0';
	}
	else
	{
		res = 'a' + temp - 10;
	}
	return res;
}
long long changeNum(string bstr)//2进制字符串转10进制正数
{
	long long res = 0;
	int x = 0;//2的次方
	for (int i = bstr.size() - 1; i >= 0; i--)
	{
		res += (bstr[i] - '0') * pow(2, x);
		x++;
	}
	return res;
}
//包结构体
class Packet
{
public:
	int _num;//包编号
	string _date;//存入时间
	string _infor;//包信息
};

//数据包头部结构体
class IP
{
public:
	void ipAnalysis(string ipstr)
	{
		//1.版本协议
		//string version= ipstr.substr(0, 4);
		int version = changeNum(ipstr.substr(0, 4));//转成数字
		if (version == 4)
		{
			_version = version + '0';
			cout << "Version:" << _version << endl;
		}
		//2.ip头部长度
		_headLength = changeNum(ipstr.substr(4, 4));//下标4开始
		cout << "Head Length:" << _headLength * 4 << "bytes" << endl;
		//3.总长度
		_totalLength= changeNum(ipstr.substr(16, 16));//下标16开始
		cout << "Total Length:" << _totalLength << endl;
		//4.标识符
		string identi = ipstr.substr(32, 16);//下标32开始
		string child;
		for (int i = 0; i < identi.size(); i++)
		{
			child += identi[i];
			if (child.size() == 4)
			{
				_identiNum += changeHex(child);
				child = "";
			}
		}
		cout << "Identification: 0x" << _identiNum << endl;
		//5.标志位 
		string sign = "0";
		sign += ipstr.substr(48, 3);
		_signNum = changeHex(sign);
		cout << "Flags: 0x" << _signNum << endl;
		//6.偏移值
		_offNum = changeNum(ipstr.substr(51, 13));
		cout << "Fragment Offset:" << _offNum << endl;
		//7.生存期
		_alive= changeNum(ipstr.substr(64, 8));
		cout << "Time to Live:" << _alive << endl;
		//8.协议
		int protocol = changeNum(ipstr.substr(72, 8));
		if (protocol == 6)
		{
			_agreement = "TCP";
		}
		else if (protocol == 1)
		{
			_agreement = "ICMP";
		}
		else if (protocol == 17)
		{
			_agreement = "UDP";
		}
		cout << "Protocol:" << _agreement << "(" << protocol << ")" << endl;
		//9.报头校验和
		string chesum = ipstr.substr(80, 16);
		child = "";
		for (int i = 0; i < chesum.size(); i++)
		{
			child += chesum[i];
			if (child.size() == 4)
			{
				_headChecSum += changeHex(child);
				child = "";
			}
		}
		cout << "Header CheckSum:Ox" << _headChecSum << endl;

		//10.源ip地址 96起始，32个字节
		string s1 = to_string(changeNum(ipstr.substr(96, 8)));
		string s2 = to_string(changeNum(ipstr.substr(104, 8)));
		string s3 = to_string(changeNum(ipstr.substr(112, 8)));
		string s4 = to_string(changeNum(ipstr.substr(120, 8)));
		_sourAddr += s1;
		_sourAddr += ".";
		_sourAddr += s2;
		_sourAddr += ".";
		_sourAddr += s3;
		_sourAddr += ".";
		_sourAddr += s4;
		cout << "Source Address:" << _sourAddr << endl;

		//11.目的ip地址
		string d1 = to_string(changeNum(ipstr.substr(128, 8)));
		string d2 = to_string(changeNum(ipstr.substr(136, 8)));
		string d3 = to_string(changeNum(ipstr.substr(144, 8)));
		string d4 = to_string(changeNum(ipstr.substr(152, 8)));
		_desAddr += d1;
		_desAddr += ".";
		_desAddr += d2;
		_desAddr += ".";
		_desAddr += d3;
		_desAddr += ".";
		_desAddr += d4;
		cout << "Destination Address:" << _desAddr << endl; 
	}
	string GetAgreement()
	{
		return _agreement;
	}
private:
	string _version;//版本协议
	int _headLength;//报头长度
	int _totalLength;//总长度
	string _identiNum;//标识符
	string _signNum;//标志位
	int _offNum;//偏移值
	int _alive;//生存期
	string _agreement;//协议
	string _headChecSum;//报头校验和
	string _sourAddr;//源ip地址
	string _desAddr;//目的ip地址
};

class TCP
{
public:
	void tcpAnalysis(string tcpstr)
	{
		//1.源端口
		_sourPort = changeNum(tcpstr.substr(0, 16));
		cout << "Source Port:" << _sourPort << endl;
		//2.目的端口
		_desPort= changeNum(tcpstr.substr(16, 16));
		cout << "Destination Port:" << _desPort << endl;
		//3.序号
		_seqNum = to_string(changeNum(tcpstr.substr(32, 32)));
		cout << "Sequence Number:" << _seqNum << endl;
		//4.确认号
		_ackNum = to_string(changeNum(tcpstr.substr(64, 32)));
		cout << "Acknowledgment Number:" << _ackNum << endl;
		//5.包头部长度
		_headLength= changeNum(tcpstr.substr(96, 4));//首部长度单位为4B
		cout << "Head Length:" << _headLength*4 << endl;
		//6.窗口大小
		_winSize= changeNum(tcpstr.substr(96+16, 16));
		cout << "Window:" << _winSize << endl;

	}
private:
	int _sourPort;//源端口
	int _desPort;//目的端口
	string _seqNum;//序号
	string _ackNum;//确认号
	int _headLength;//长度
	int _winSize;//窗口大小
};

class UDP
{
public:
	void udpAnalysis(string udpstr)
	{
		//1.源端口
		_sourPort = changeNum(udpstr.substr(0, 16));
		cout << "Source Port: " << _sourPort << endl;
		//2.目的端口
		_desPort = changeNum(udpstr.substr(16, 16));
		cout << "Destination Port: " << _desPort << endl;
		//3.报文长度
		_length = changeNum(udpstr.substr(32, 16));
		cout << "Length: " << _length << endl;
		//4.首部校验和
		string checsum = udpstr.substr(48, 16);//下标32开始
		string child;
		for (int i = 0; i < checsum.size(); i++)
		{
			child += checsum[i];
			if (child.size() == 4)
			{
				_headChecSum += changeHex(child);
				child = "";
			}
		}
		cout << "Checksum: 0x" << _headChecSum << endl;
	}
private:
	int _sourPort;//源端口
	int _desPort;//目的端口
	//首部长度固定8个字节
	int _length;//udp数据报总长度
	string _headChecSum;//首部校验和
};

class ICMP
{
public:
	void icmpAnalysis(string icmpstr)
	{
		//1.报文类型
		int typenum = changeNum(icmpstr.substr(0, 8));
		switch(typenum)
		{
		case 0:_type = "Echo request";
			break;
		case 5:_type = "Redirect for host";
			break;
		case 8:_type = "Echo Reply";
			break;
		case 11:_type = "TTL equals 0 during transit";
			break;
		case 12:_type = "IP header bad (catchall error)";
			break;
		case 13:_type = "Timestamp request ";
			break;
		}
		cout << "Type: " << _type << endl;
		//2.错误原因
		_code = changeNum(icmpstr.substr(8, 8));
		cout << "Code: " << _code << endl;
		//3.检验和
		string checsum = icmpstr.substr(16, 16);//下标32开始
		string child;
		for (int i = 0; i < checsum.size(); i++)
		{
			child += checsum[i];
			if (child.size() == 4)
			{
				_checkSum += changeHex(child);
				child = "";
			}
		}
		cout << "Checksum: 0x" << _checkSum << endl;
	}
private:
	string _type;//报文类型
	int _code;//错误原因
	string _checkSum;//检验和
};

bool connectDB(MYSQL& mysql)
{
	// 1.初始化数据库句柄
	mysql_init(&mysql);

	// 2.设置字符编码
	mysql_options(&mysql, MYSQL_SET_CHARSET_NAME, "gbk");

	// 3.连接数据库										// 账号	  密码         数据库名
	MYSQL* ret = mysql_real_connect(&mysql, "127.0.0.1", "root", "zss060310", "packet", 3306, NULL, 0);
	if (ret == NULL) {
		cout << "connect error:" << mysql_error(&mysql);
		return false;
	}
	cout << "connect success." << endl;

	// 选择数据库
	int res = mysql_select_db(&mysql, "packet");
	if (res) 
	{
		cout << "choose error:" << mysql_error(&mysql) << endl;
		return false;
	}
	cout << "choose success." << endl;
	return true;
}


bool queTableData(vector<Packet>& vp)
{
	MYSQL mysql;		// 数据库句柄
	MYSQL_RES* res;		// 查询结果集
	MYSQL_ROW row;		// 记录结构体
	char sql[SQL_MAX];	// 保存SQL语句

	// 连接数据库
	if (!connectDB(mysql)) 
	{
		return false;
	}

	// C语言组合字符串
	snprintf(sql, SQL_MAX, "SELECT id, time, packet FROM packet;");
	cout << "sql:" << sql << endl;

	// 查询
	int ret = mysql_real_query(&mysql, sql, (unsigned long)strlen(sql));

	if (ret) {
		cout << "select error:" << mysql_error(&mysql) << endl;
		return false;
	}
	cout << "select success." << endl;

	// 获取结果集
	res = mysql_store_result(&mysql);

	// 获取数据,将结果插入vp数组，并打印
	while (row = mysql_fetch_row(res)) 
	{
		Packet p;
		p._num = atoi(row[0]);
		p._date = row[1];
		p._infor = row[2];
		vp.push_back(p);
		cout << p._num << " " << p._date << " " << p._infor << " " << endl;
		cout << endl;
	}
	// 释放结果集
	mysql_free_result(res);
	// 关闭数据库
	mysql_close(&mysql);
	return true;
}


void Analysis(vector<Packet> vp)
{
	for (int i = 0; i < vp.size(); i++)
	{
		cout << "PacketNum:" << "<<" << i + 1 << ">>" << endl;
		string usestr = changeBin(vp[i]._infor);//16进制转2进制字符串
		//测试
		//cout << usestr << endl;

		/*1.网络层IP包头部信息*/
		cout << "*Internet Protocol*" << endl;
		IP ip;
		int iphead = changeNum(usestr.substr(116, 4)) * 4 * 8;//ip头部长度
		ip.ipAnalysis(usestr.substr(112, iphead));//ip:从112+长度个字节开始存储
		cout << endl;

		/*2.传输层*/
		
		//根据ip内封装的协议判断
		string agreement = ip.GetAgreement();
		if (agreement == "TCP")
		{
			cout << "*Transmission Control Protocol *" << endl;
			TCP tcp;
			int tcpstart = 112 + iphead;
			int tcphead = changeNum(usestr.substr(tcpstart + 96, 4)) * 4 * 8;//tcp头部长度
			tcp.tcpAnalysis(usestr.substr(tcpstart, tcphead));
			cout << endl;
		}
		else if (agreement == "UDP")
		{
			cout << "*User Datagram Protocol*" << endl;
			UDP udp;
			int udpstart= 112 + iphead;
			udp.udpAnalysis(usestr.substr(udpstart, 64));//udp首部固定8个字节
			cout << endl;
		}
		else if (agreement == "ICMP")
		{
			cout << "*Internet Control Message Protocol *" << endl;
			ICMP icmp;
			int icmpstart = 112 + iphead;
			icmp.icmpAnalysis(usestr.substr(icmpstart, 32));//只需要分析32个比特位的信息
			cout << endl;
		}
	}

}
int main()
{
	//1.连接数据库，将结果保存到packet对象数组
	vector<Packet> vp;
	queTableData(vp);

	//2.协议分析
	Analysis(vp);
	return 0;
}
