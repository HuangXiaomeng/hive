create table encode_test1(id INT, name STRING, phone STRING, address STRING)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe'
WITH SERDEPROPERTIES ('column.encode.columns'='phone,address', 'column.encode.classname'='org.apache.hadoop.hive.serde2.Base64WriteOnly')
STORED AS TEXTFILE;

create table encode_test2(id INT, name STRING, phone STRING, address STRING)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe'
WITH SERDEPROPERTIES ('column.encode.indices'='2,3', 'column.encode.classname'='org.apache.hadoop.hive.serde2.Base64Rewriter')
STORED AS TEXTFILE;

from src tablesample (2 rows)
insert into table encode_test1 select key,'navis',concat('010-0000-', key), concat('Seoul.', value)
insert into table encode_test2 select key,'navis',concat('010-0000-', key), concat('Seoul.', value);

select * from encode_test1;
select * from encode_test2;
