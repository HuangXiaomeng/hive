create table encode_test1(id INT, name STRING, phone STRING, address STRING)
STORED BY 'org.apache.hadoop.hive.hbase.HBaseStorageHandler' WITH SERDEPROPERTIES (
'hbase.columns.mapping' = ':key,private:name,private:phone,private:address',
'column.encode.columns'='phone,address', 'column.encode.classname'='org.apache.hadoop.hive.serde2.Base64WriteOnly');

create table encode_test2(id INT, name STRING, phone STRING, address STRING)
STORED BY 'org.apache.hadoop.hive.hbase.HBaseStorageHandler' WITH SERDEPROPERTIES (
'hbase.columns.mapping' = ':key,private:name,private:phone,private:address',
'column.encode.indices'='2,3', 'column.encode.classname'='org.apache.hadoop.hive.serde2.Base64Rewriter');

from src tablesample (2 rows)
insert into table encode_test1 select key,'navis',concat('010-0000-', key), concat('Seoul.', value)
insert into table encode_test2 select key,'navis',concat('010-0000-', key), concat('Seoul.', value);

select * from encode_test1;
select * from encode_test2;
