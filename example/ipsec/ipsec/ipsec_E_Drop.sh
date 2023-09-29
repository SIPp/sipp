#!/bin/bash
#
# User Endpoint drop all 4 SA
#
# \author Dragos Vingarzan vingarzan -at- fokus dot fraunhofer dot de
# \author xfrm Serge S. Yuriev  nevian -at- nevian dot org
#

ue=$1
port_uc=$2
port_us=$3

pcscf=$4
port_pc=$5
port_ps=$6

spi_uc=$7
spi_us=$8

spi_pc=$9
spi_ps=${10}



ip xfrm policy del src $ue dst $pcscf sport $port_uc dport $port_ps dir out
ip xfrm state del src $ue dst $pcscf proto esp spi $spi_ps

ip xfrm policy del src $ue dst $pcscf sport $port_us dport $port_pc dir out
ip xfrm state del src $ue dst $pcscf proto esp spi $spi_pc

ip xfrm policy del src $pcscf dst $ue sport $port_ps dport $port_uc dir in
ip xfrm state del src $pcscf dst $ue proto esp spi $spi_uc

ip xfrm policy del src $pcscf dst $ue sport $port_pc dport $port_us dir in
ip xfrm state del src $pcscf dst $ue proto esp spi $spi_us
