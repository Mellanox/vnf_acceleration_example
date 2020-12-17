#vnf_acceleration_example

This repository is meant to provide a VNF example application.
There are three examples in this repository:
* Decap 
* Encap
* RSS 

The main function:

The main function initializes the EAL, allocates a mempool
to hold the mbufs, initializes the ports, creates the flows 
and runs the main loop which reads the packets from all queues 
and prints details for each packet.
The main creates all three example flows. 

Decap example:

The decap example matches on the following header:
eth / ipv4 / udp / gtp type 255 / ipv4 src addr is 10.10.10.10 /
udp proto is 4000
The outer part is decaped from L2 up to and including the tunnel
then the packet is encaped with missing L2,
we set new IPv4 src address, and perform RSS.

Encap example:

The encap example matches on the following header:
ipv4 src addr is 10.10.10.10 dst addr is 11.11.11.11 /
udp proto is 4000
L2 is decaped and then all layers including tunnel are encaped using 
initiated structures.

RSS example:

The RSS example matches on the following header:
eth / ipv4 / udp / gtp type 255 /  ipv4 / udp
then RSS is performed on the packet based on L3 src only.

Sync flow example:

Two functions are implemented which sync flows in NIC TX domain and all
domain.
If fail, the application will quit with error.

Hairpin example:

The hairpin example will setup one haipin queue. And according to the ports
used: one or two, different hairpin setup will be used:
1. one port hairpin;
2. two port hairpin;

For one port hairpin, mode .manual_bind = 0 & .tx_explicit = 0 is used which
means PMD will bind haripin queues automaticly and implicitly create Tx flow.
The application only insert one ingress flow which match on:
eth / ipv4 src is 10.10.10.10 / tcp
with actions:
queue index <hairpin queue> / raw_decap / raw_encap
The packet is directed to hairpin queue and on Tx direction the L2 is decaped
with GTP-U header.

Fow two ports hairpin, mode .manual_bind = 1 & .tx_explicit = 1 is the only
mode can be supported today.
The application, then, manually call hairpin bind API and create Tx flow
explicitly to decap L2 with GTP-U header as it did in one port hairpin.

Flow Tag example:

This example creates two flows: one is on root table, one is on group 1.
The rule on root table matchs following packet:
eth / ipv4 / udp / gtp type 255 teid is 0x1200 / ipv4 src is 10.10.10.10 / tcp
A tag is set on the matched packet and jump to group 1 to do continue actions.
The rule on group 1 only match on the TAG value and decap GTP header with L2.

Sampling and Mirror example:

This example has two functions, one creates a flow with 50% sampling rate
which matchs:
eth / ipv4 / udp / gtp teid is 1234 type 255 / ipv4 src is 12.10.10.10 / tcp
the sampled packet has different markid from normal forward packet.

The other creates an FDB rule with mirror in switchdev mode which matchs:
eth / ipv4 / udp / gtp teid is 1234 type 255 / ipv4 src is 13.10.10.10 / tcp
This function need to run in switchdev mode (i.e, -a 81:00.0,representor=0).

Symmetric RSS example:

This example creates one flow for Uplink which matchs on:
eth / ipv4 / udp / gtp geid is 1234 type 255 / ipv4 src is 2.0.0.1 / tcp
The inner ipv4 src address is UE's IP.

The other flow is for Downlink which matchs on:
eth / ipv4 dst is 2.0.0.1 / tcp
The ipv4 dst address is UE's IP, which is as same as Uplink's src address.
By using symmetric RSS key and hash on field IP src and dst fields, the Uplink
and downlink of the same session should go to the same queue but different
session will be spreaded on RSS queues.

Meter example:

This example creates one srTCM profile which has cir 1MB, cbs 64KB and
one shared meter object using the above profile.
One jump flow is created on root table which matchs on:
eth / ipv4 / udp / gtp teid is 1234 type 255 / ipv4 src is 13.10.10.10 / tcp
If packet is matched, tag is set and jump to the next table on group 1 which
matchs on tag. The meter is attached to this flow.

GTP QFI match example:

This example match on GTP traffice as following:
eth / ipv4 src is 3.3.1.1 / udp / gtp teid is 1234 v_pt_rsv_flags spec 0x04 v_pt_rsv_flags mask 0x07 mst_type is 255 / gtp_psc qfi is 9 pdu_t is 0x10 / end

How to run the Application:

Clone the Mellanox DPDK from:  
https://github.com/Mellanox/dpdk.org  
git clone git@github.com:Mellanox/dpdk.org.git

Make sure you have all the MLX5 DPDK Prerequisites:  
https://doc.dpdk.org/guides/nics/mlx5.html#prerequisites

Compile and build the DPDK:  
https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html  
meson build-meson  
cd build-meson  
ninja 

Clone the VNF example repository:  
https://github.com/Mellanox/vnf_acceleration_example  
git clone git@github.com:Mellanox/vnf_acceleration_example.git

Set the environment variables:  
export RTE_SDK=/path/to/dpdk/folder  
export RTE_TARGET=export_target(for example: x86_64-native-linuxapp-gcc)

Configure hugepages (run as root):  
mkdir /mnt/huge  
mount nodev -t hugetlbfs -o rw,pagesize=2M /mnt/huge  
echo 4096 > /sys/devices/system/node/node0/hugepages/hugepages-2048kB/nr_hugepages

Enable GTP flex parser(run as root):  
mst start  
mst status -v  
locate the NIC's MST name (for example /dev/mst/mt4125_pciconf0)  
mlxconfig -d /dev/mst/mt4125_pciconf0 set FLEX_PARSER_PROFILE_ENABLE=3

Reset the firmware:  
mlxfwreset -d 00:08.0 reset -y

In the cloned VNF folder, run:  
make

To run the application:  
sudo ./build/vnf_example -l 1 -n 1 -w 00:08.0  
parameters:  
-l - List of cores to run on.  
-n - Set the number of memory channels to use.  
-w - Add a PCI device in white list.  

To exit application:  
ctrl+c

