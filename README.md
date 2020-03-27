# crossnet
打通到内网的通路，实现在外部访问内网web服务器、远程连接内网windows、linux等功能。

devel:
	yum install -y make
	yum install -y openssl-devel
	yum install -y json-c-devel
	yum install -y mysql-devel
	tar -zxvf libiconv-1.15.tar.gz && ./configure && make && make install 
	ldconfig

transfer ip address to location
usage:

    display
        curl "http://127.0.0.1:800/debug?display_g_user_table"
        curl "http://127.0.0.1:800/debug?display_g_domain_map_table"

    add_account
        curl "http://127.0.0.1:800/add_account?user_name=xx&password=yy&domain=www.david.com&end_time=1593399542&total_flow=200000"

    mdf_account
        curl "http://127.0.0.1:800/mdf_account?user_name=xx&password=yy&domain=www.david.com&end_time=1593399542&total_flow=100000&used_flow=2"

    del_account
        curl "http://127.0.0.1:800/del_account?user_name=xx"

    query_account
        curl "http://127.0.0.1:800/query_account?user_name=xx"

