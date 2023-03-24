
#include<iostream>
#include <mysql.h> // mysql文件
using namespace std;
#define SQL_MAX 256		// sql语句字符数组最大值

//数据包头部结构体
struct IP
{
	string version;//版本协议
	int headLength;//报头长度
	int totalLength;//总长度
	int identiNum;//标识符
	int signNum;//标志位
	int offNum;//偏移值
	int alive;//生存期
	string agreement;//协议
	int headChecSum;//报头校验和
	string desAddr;//源ip地址
	string sourAddr;//目的ip地址
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
		printf("数据库连接失败！失败原因：%s\n", mysql_error(&mysql));
		return false;
	}

	printf("数据连接成功！\n");

	// 选择数据库，成功返回0，失败返回非0
	int res = mysql_select_db(&mysql, "packet");
	if (res) {
		printf("选择数据库失败！失败原因%s\n", mysql_error(&mysql));
		return false;
	}
	printf("数据库选择成功！\n");

	return true;
}

bool queTableData() 
{
	MYSQL mysql;		// 数据库句柄
	MYSQL_RES* res;		// 查询结果集
	MYSQL_ROW row;		// 记录结构体
	char sql[SQL_MAX];	// SQL语句

	// 连接数据库
	if (!connectDB(mysql)) {
		return false;
	}

	// C语言组合字符串
	snprintf(sql, SQL_MAX, "SELECT id, time, packet FROM packet;");
	printf("查询sql语句：%s\n", sql);

	// 查询数据
	//int ret = mysql_query(&mysql, "select * from student;");		// 等效于下面一行代码
	//int ret = mysql_query(&mysql, sql);
	int ret = mysql_real_query(&mysql, sql, (unsigned long)strlen(sql));
	printf("执行查询语句，查询返回结果：%d\n", ret);

	if (ret) {
		printf("数据查询失败！失败原因：%s\n", mysql_error(&mysql));
		return false;
	}
	printf("数据查询成功！\n");


	// 获取结果集
	res = mysql_store_result(&mysql);

	// 获取查询到的一行数据
	// 给row赋值，判断row是否为空，不为空就打印数据。
	while (row = mysql_fetch_row(res)) 
	{
		cout << atoi(row[0])<<"  " << row[1] << "  "<<row[2] << endl;
		cout << endl;
	}

	// 释放结果集
	mysql_free_result(res);

	// 关闭数据库
	mysql_close(&mysql);

	return true;
}

int main()
{
	//1.连接数据库
	queTableData();
	return 0;
}
