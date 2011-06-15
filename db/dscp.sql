-- RCC: Really Comprehensive Classifier

-- drop schema public cascade;
drop schema wireless cascade;
drop schema network cascade;
drop schema threats cascade;

-- create schema public;
create schema wireless;
create schema network;
create schema threats;

set search_path = network, wireless, threats, public, pg_catalog;

create domain protocol_t as smallint default 6 not null;
create domain port_t as smallint default 0 not null;
create domain name_t as varchar(20);
create domain diffserv_t as varchar(4) default 'BE' NOT NULL;
create domain priority_t as smallint check (value between -1 and 8); 
create domain cwin_t smallint check (value between -1 and 1024); 
create domain aifsn_t smallint check (value between -1 and 1024); 
create domain max_txop_t float; -- time value in ms
create domain codepoint_t smallint check (value between -1 and 64);
create domain description_t varchar(40);
create domain service_t varchar(4);

create table protocols (
       id smallint not null,
       proto_name name_t,
       description description_t,
       primary key(id));

create table port_map (
       port port_t,
       port_type smallint references protocols(id),
       primary key(port)
);


-- create table threat_port_map (
--       port port_t,
--       port_type smallint references protocols.id,
-- );

create view tcp_port_map as 
       select port from port_map where port_type = 6;

-- Some data sources

-- drop table diffserv cascade;

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
       cp codepoint_t,
       primary key(id), unique(cp));

create table mac8021d_map(
       id service_t not null,
       cp priority_t not null,
       priority priority_t,
       description description_t,
       primary key(id));

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

create view diffserv_tos_v as 
       select id,cp,cp_hex,(cp_bit::bit(6) << 3)::bit(3) as prio 
              from diffserv_v;

set search_path = wireless, network, threats, public, pg_catalog;

create table mac80211e_map (
       id service_t,
       cp priority_t,
       priority priority_t,
       description description_t,
       primary key(cp), unique(id));

create table edca_map(
       ac service_t, 
       cwmin cwin_t,
       cwmax cwin_t,
       aifsn aifsn_t,
       max_txop max_txop_t,
       priority priority_t,
       description description_t, 
       primary key(ac));

insert into edca_map VALUES('BK',31,1023,7,0,0,'Background');
insert into edca_map VALUES('BE',31,1023,3,0,1,'Best Effort');
insert into edca_map VALUES('VI',15,31,2,3.008,2,'Video 3ms');
insert into edca_map VALUES('VO',7,15,2,1.5004,3,'Voice 1.5ms');
insert into edca_map VALUES('DCF',15,1023,2,0,1,'Legacy DCF');

insert into mac80211e_map values('BK',0);
insert into mac80211e_map values('BE',1);
insert into mac80211e_map values('VI',3);
insert into mac80211e_map values('VO',4);

insert into mac8021d_map values('BK',1,0,'Background');
insert into mac8021d_map values('BE',0,1,'Best Effort');
insert into mac8021d_map values('EE',2,2,'Excellent Effort');
insert into mac8021d_map values('CR',3,3,'Critical Applications');
insert into mac8021d_map values('VI',4,4,'Video sub 100ms latency');
insert into mac8021d_map values('VO',5,5,'Audio sub 10ms latency');
insert into mac8021d_map values('IC',6,6,'Internetwork Control');
insert into mac8021d_map values('NC',7,7,'Network Control');

-- gotta think about these
create table d2e_map (
       d_prio priority_t,
       d_map service_t references mac8021d_map(id), 
       e_prio priority_t,
       e_map service_t references mac80211e_map(id),
       primary key(d_prio));

-- This is currently wrong, find source

insert into d2e_map values (0,'BE',1,'BE');
insert into d2e_map values (1,'BK',0,'BK');
insert into d2e_map values (2,'EE',0,'BK');
insert into d2e_map values (3,'CR',1,'BE');
insert into d2e_map values (4,'VI',2,'VI');
insert into d2e_map values (5,'VO',3,'VO');
insert into d2e_map values (6,'IC',3,'VO');
insert into d2e_map values (7,'NC',3,'VO');

-- create view e2d_map

-- so I can ultimately get to figuring out how dscp is 
-- currently mapping to wireless

-- HCCA?

-- And this is still wrong, or so I hope.

create view dscp_8021d_v as select d.id as id, d.cp as cp, d.prio as prio ,m.id as mac8021d_prio 
              from diffserv_prio_v d, mac8021d_map m 
	      where d.prio::integer = m.priority;


create view dscp_80211e_v as select d.id as id, d.cp as cp, d.prio as prio ,m.id as mac80211e_prio 
              from diffserv_prio_v d, mac80211e_map m 
	      where d.prio::integer = m.priority;
