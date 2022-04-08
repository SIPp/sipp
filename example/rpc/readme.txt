################################################################
#Instructions to build rpc interface
#you will need the client sa_ctl to send rpc commands to sipp
#Example: sa_ctl get_callcount will get the current call count
#
Steps to regenerate the files:: 
0. Make a new .x file with whatever commands you're trying to implement
1. Install the portmap service which is required for rpc services - apt-get install portmap
2. Start clean -  make clean
3. Backup any mods you might have made - cp sipp-rpc_client.c sipp-rpc_client.c.bak
4. Regenerate a new raw client  - rpcgen -M -C -a sipp-rpc.x
5. Restore your old mods, or modify the client as needed - cp sipp-rpc_client.c.bak sipp-rpc_client.c
6. Build it - make - this will build a client and server for testing or use the client to try your new commands out on a compatible server process - like sipp!
