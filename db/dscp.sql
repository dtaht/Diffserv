-- RCC: Really Comprehensive Classifier

create domain diffserv_t as varchar(4) default 'BE' NOT NULL;

drop table diffserv cascade;

create table diffserv (
       id diffserv_t,
       cp smallint check (cp > -1 AND cp < 64),
       primary key(id), unique(cp));

insert into diffserv values ('BE',0);
insert into diffserv values ('EF',46); 
insert into diffserv values ('AF11',10); 
insert into diffserv values ('AF12',12);
insert into diffserv values ('AF13',14); 
insert into diffserv values ('AF21',18); 
insert into diffserv values ('AF22',20); 
insert into diffserv values ('AF23',22); 
insert into diffserv values ('AF31',26); 
insert into diffserv values ('AF32',28); 
insert into diffserv values ('AF33',30); 
insert into diffserv values ('AF41',34); 
insert into diffserv values ('AF42',36); 
insert into diffserv values ('AF43',38); 
insert into diffserv values ('CS1',8); 
insert into diffserv values ('CS2',16);
insert into diffserv values ('CS3',24);
insert into diffserv values ('CS4',32);
insert into diffserv values ('CS5',40);
insert into diffserv values ('CS6',48);
insert into diffserv values ('CS7',56);

-- unofficial

insert into diffserv values ('BOFH',4); -- OR IT
insert into diffserv values ('LB',63);
insert into diffserv values ('MICE',42);
insert into diffserv values ('P2P',33);

create view diffserv_v as select id, cp, to_hex(cp::integer) cp_hex,cp::integer::bit(6) as cp_bit from diffserv; 
