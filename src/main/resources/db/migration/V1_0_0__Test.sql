create table activity (id bigint generated by default as identity, description varchar(255), performed_by_id bigint, primary key (id));
create table employee (id bigint generated by default as identity, name varchar(255), primary key (id));
alter table activity add constraint FKrf5dckkcm44xo5u1ehajux0sm foreign key (performed_by_id) references employee;
