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

