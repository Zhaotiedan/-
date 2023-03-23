catch:catch.c
	gcc -o $@ $^ -lpcap -L/usr/lib64/mysql -lmysqlclient 
.PHONY:clean
clean:
	rm -f catch
