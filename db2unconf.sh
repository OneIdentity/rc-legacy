#!/bin/sh
db2 update dbm cfg using SRVCON_PW_PLUGIN NULL
db2 update dbm cfg using GROUP_PLUGIN NULL
db2 update dbm cfg using CLNT_PW_PLUGIN NULL

