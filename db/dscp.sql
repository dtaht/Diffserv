-- RCC: Really Comprehensive Classifier

create domain diffserv_t as varchar(4) default 'BE' NOT NULL;

drop table diffserv cascade;

-- from /etc/iproute2
-- 
-- These all need to be shifted right 2
-- field not including ecn
-- 0x00	default
-- 0x10	lowdelay
-- 0x08	throughput
-- 0x04	reliability
-- # This value overlap with ECT, do not use it!
-- 0x02	mincost
-- Cisco
-- 0x20	priority
-- 0x40	immediate
-- 0x60	flash
-- 0x80	flash-override
-- 0xa0	critical
-- 0xc0	internet
-- 0xe0	network
-- 0x28	AF11
-- 0x30	AF12
-- 0x38	AF13
-- 0x48	AF21
-- 0x50	AF22
-- 0x58	AF23
-- 0x68	AF31
-- 0x70	AF32
-- 0x78	AF33
-- 0x88	AF41
-- 0x90	AF42
-- 0x98	AF43

-- And wikipedia defines

-- 111 	0xE0 	224 	Network Control
-- 110 	0xC0 	192 	Internetwork Control
-- 101 	0xA0 	160 	CRITIC/ECP
-- 100 	0x80 	128 	Flash Override
-- 011 	0x60 	96 	Flash
-- 010 	0x40 	64 	Immediate
-- 001 	0x20 	32 	Priority
-- 000 	0x00 	0 	Routine

create table diffserv (
       id diffserv_t,
       cp smallint check (cp > -1 AND cp < 64),
       primary key(id), unique(cp));

-- copy the diffserv table for tos

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

-- TOS-style

-- insert into diffserv values ('RELI',1); -- reliability
-- insert into diffserv values ('THRU',2); -- throughput
-- insert into diffserv values ('LD',4); -- low delay


-- unofficial

insert into diffserv values ('BOFH',4); -- OR IT or LD
insert into diffserv values ('LB',63);
insert into diffserv values ('MICE',42);
insert into diffserv values ('P2P',33); -- CS1 | RELI should be WORSE than CS1

create view diffserv_v as 
       select id, cp, to_hex(cp::integer) cp_hex,
       	      cp::integer::bit(6) as cp_bit 
	      from diffserv; 

create view diffserv_prio_v as 
       select id,cp,cp_hex,cp_bit::bit(3) as prio 
              from diffserv_v;

drop table mac80211e_map cascade;

create table mac80211e_map (
       id varchar(2) not null, 
       cp smallint check (cp > -1 and cp < 8), 
       primary key(cp));

drop table mac8021d_map cascade;

create table mac8021d_map(
       id varchar(2) not null, 
       cp smallint check (cp > -1 and cp < 8), 
       description varchar(40), 
       priority smallint check (priority > -1 and priority < 8),
       primary key(cp));

insert into mac80211e_map values('BE',0);
insert into mac80211e_map values('VO',1);
insert into mac80211e_map values('VO',2);
insert into mac80211e_map values('BE',3);
insert into mac80211e_map values('VI',4);
insert into mac80211e_map values('VI',5);
insert into mac80211e_map values('BK',6);
insert into mac80211e_map values('BK',7);

insert into mac8021d_map values('BK',1,'Background',0);
insert into mac8021d_map values('BE',0,'Best Effort',1);
insert into mac8021d_map values('EE',2,'Excellent Effort',2);
insert into mac8021d_map values('CR',3,'Critical Applications',3);
insert into mac8021d_map values('VI',4,'Video sub 100ms latency',4);
insert into mac8021d_map values('VO',5,'Audio sub 10ms latency',5);
insert into mac8021d_map values('IC',6,'Internetwork Control',6);
insert into mac8021d_map values('NC',7,'Network Control',7);

-- gotta think about these
-- create view d2e_map as select 
-- create view e2d_map

-- so I can ultimately get to figuring out how dscp is 
-- currently mapping to wireless