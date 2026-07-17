#!/bin/bash
set -e

NS1="netns1"
NS2="netns2"
VETH1="veth1"
VETH1_P="veth1-p"
VETH2="veth2"
VETH2_P="veth2-p"

# vxlan-a/vxlan-b stand in for the underlay uplinks of two separate VTEPs
# (VTEP-A owns veth1's access side, VTEP-B owns veth2's) collapsed onto one
# host for lab purposes. This is a genuine veth pair (both ends stay in the
# host root namespace) so that redirecting onto it, then decapsulating on
# the peer, is a real second hop rather than a single in-place rewrite.
VXLAN_A="vxlan-a"
VXLAN_B="vxlan-b"
VXLAN_A_IP="10.10.10.1/30"
VXLAN_B_IP="10.10.10.2/30"

echo "Cleaning up leftover nets1 and/or netns2 network namespaces..."
ip netns del $NS1 2>/dev/null || true
ip netns del $NS2 2>/dev/null || true
ip link del $VETH1 2>/dev/null || true
ip link del $VETH2 2>/dev/null || true
ip link del $VXLAN_A 2>/dev/null || true

echo "Creating netns1 and netns2 netnetwork namespaces..."
ip netns add $NS1
ip netns add $NS2

echo "Creating veth pairs..."
ip link add $VETH1 type veth peer name $VETH1_P
ip link add $VETH2 type veth peer name $VETH2_P
ip link add $VXLAN_A type veth peer name $VXLAN_B

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

echo "Configuring the vxlan-a/vxlan-b underlay link and bringing it up"
ip addr add $VXLAN_A_IP dev $VXLAN_A
ip addr add $VXLAN_B_IP dev $VXLAN_B
ip link set $VXLAN_A up
ip link set $VXLAN_B up

clang -O2 -g -I /usr/include/$(uname -m)-linux-gnu -target bpf -c ./bpf/dummy.c -o dummy.o

# Attach dummy XDP program to network namespace links
sudo ip netns exec netns1 ip link set dev veth1-p xdp obj dummy.o sec xdp
sudo ip netns exec netns2 ip link set dev veth2-p xdp obj dummy.o sec xdp

# Attach dummy XDP to both ends of the vxlan-a/vxlan-b underlay pair for now.
# Native-mode veth redirect needs an XDP program on both ends of a pair to
# actually deliver frames (see M3W1 postmortem) - these will be replaced by
# the real encap/decap program once it lands.
sudo ip link set dev $VXLAN_A xdp obj dummy.o sec xdp
sudo ip link set dev $VXLAN_B xdp obj dummy.o sec xdp

echo "Disabling IPv6 on host veths reduce noise"
sysctl -w net.ipv6.conf.$VETH1.disable_ipv6=1 > /dev/null
sysctl -w net.ipv6.conf.$VETH2.disable_ipv6=1 > /dev/null
sysctl -w net.ipv6.conf.$VXLAN_A.disable_ipv6=1 > /dev/null
sysctl -w net.ipv6.conf.$VXLAN_B.disable_ipv6=1 > /dev/null

echo "Setup complete."
echo "Topology: [$NS1: 10.0.0.1/24] <----> ($VETH1 --- host --- $VETH2) <----> [$NS2: 10.0.0.2/24]"
echo "Underlay:  $VXLAN_A ($VXLAN_A_IP) <----> $VXLAN_B ($VXLAN_B_IP)"
echo ""
echo "Run these to get the constants forwarder.c will need for encap/decap:"
echo "  cat /sys/class/net/$VXLAN_A/ifindex   # VXLAN_A_IFINDEX"
echo "  cat /sys/class/net/$VXLAN_B/ifindex   # VXLAN_B_IFINDEX"
echo "  cat /sys/class/net/$VXLAN_A/address   # MAC_VXLAN_A"
echo "  cat /sys/class/net/$VXLAN_B/address   # MAC_VXLAN_B"