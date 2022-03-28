A demo of the plugin functionality of sipp with a simple lua script can be found in the docs directory.
1. sipp_demo.sh - this will executing uas_w_script.xml
2. uas_w_script.xml

Just send a call to it to see it utlize a plugin

To create and use the plugin - 
1. enable LUA and then build sipp with whatever other options you want to use.
example:
cmake . -DCMAKE_BUILD_TYPE=Debug -DUSE_GSL=0 -DUSE_SSL=1 -DUSE_SCTP=0 -DUSE_PCAP=0 -DUSE_LUA=1
2. Use the -plugin option to specify the location of your plugin.  There is a demo plugin in myapp.cpp which can be used the create libmyapp.so
3. The demo plugin adds functionality to interpret the new sipp flags -lua_file and -pid to record the pid of the file and to specify which lua script will be used 
4. The xml to call the lua script and retrieve values can be found in the xml file uas_w_script.xml


