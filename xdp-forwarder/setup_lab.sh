#!/bin/bash
set -e

NS1="netns1"
NS2="netns2"
VETH1="veth1"
VETH1_P="veth1-p"
VETH2="veth2"
VETH2_P="veth2-p"

echo "Cleaning up leftover nets1 and/or netns2 network namespaces..."
ip netns del $NS1 2>/dev/null || true
ip netns del $NS2 2>/dev/null || true
ip link del $VETH1 2>/dev/null || true
ip link del $VETH2 2>/dev/null || true

echo "Creating netns1 and netns2 netnetwork namespaces..."
ip netns add $NS1
ip netns add $NS2

echo "Creating veth pairs..."
ip link add $VETH1 type veth peer name $VETH1_P
ip link add $VETH2 type veth peer name $VETH2_P

echo "Moving veth interfaces into namespaces..."
ip link set $VETH1_P netns $NS1
ip link set $VETH2_P netns $NS2

echo "Configuring IP for netns1 and bring its links up"
ip netns exec $NS1 ip addr add 10.0.0.1/24 dev $VETH1_P
ip netns exec $NS1 ip link set $VETH1_P up
ip netns exec $NS1 ip link set lo up
ip netns exec $NS1 ip route add default dev $VETH1_P

echo "Configuring IP for netns2 and bring its links up"
ip netns exec $NS2 ip addr add 10.0.0.2/24 dev $VETH2_P
ip netns exec $NS2 ip link set $VETH2_P up
ip netns exec $NS2 ip link set lo up
ip netns exec $NS2 ip route add default dev $VETH2_P

ip link set $VETH1 up
ip link set $VETH2 up

echo "Disabling IPv6 on host veths reduce noise"
sysctl -w net.ipv6.conf.$VETH1.disable_ipv6=1 > /dev/null
sysctl -w net.ipv6.conf.$VETH2.disable_ipv6=1 > /dev/null

echo "Setup complete."
echo "Topology: [$NS1: 10.0.0.1/24] <----> ($VETH1 --- host --- $VETH2) <----> [$NS2: 10.0.0.2/24]"