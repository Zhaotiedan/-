
#include<iostream>
#include<vector>
#include<string>
#include <mysql.h> // mysql文件
using namespace std;
#define SQL_MAX 256	// sql语句字符数组最大值

string change(string infor)//16进制字符串转2进制字符串
{
	string res;
	for (int i = 0; i < infor.size(); i++)
	{
		
	}
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
		//版本
		string temp= ipstr.substr(0, 1);
		//转成二进制字符串
		//int vnum = atoi(temp);
		
	}
private:
	string _version;//版本协议
	int _headLength;//报头长度
	int _totalLength;//总长度
	int _identiNum;//标识符
	int _signNum;//标志位
	int _offNum;//偏移值
	int _alive;//生存期
	string _agreement;//协议
	int _headChecSum;//报头校验和
	string _desAddr;//源ip地址
	string _sourAddr;//目的ip地址
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
	if (!connectDB(mysql)) {
		return false;
	}

	// C语言组合字符串
	snprintf(sql, SQL_MAX, "SELECT id, time, packet FROM packet;");
	cout << "sql:" << sql << endl;
	//printf("查询sql语句：%s\n", sql);

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
	//ip:从112+长度个字节开始存储

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
