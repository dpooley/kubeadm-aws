#!/bin/bash -ve

# Disable pointless daemons
systemctl stop snapd snapd.socket lxcfs snap.amazon-ssm-agent.amazon-ssm-agent
systemctl disable snapd snapd.socket lxcfs snap.amazon-ssm-agent.amazon-ssm-agent

# Disable swap to make K8S happy
swapoff -a
sed -i '/swap/d' /etc/fstab

# Install K8S, kubeadm, crio
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add -
gpg --keyserver keyserver.ubuntu.com --recv 8BECF1637AD8C79D && gpg --export --armor 8BECF1637AD8C79D | apt-key add -
echo "deb http://apt.kubernetes.io/ kubernetes-xenial main" > /etc/apt/sources.list.d/kubernetes.list
echo "deb http://ppa.launchpad.net/projectatomic/ppa/ubuntu xenial main" > /etc/apt/sources.list.d/project-atomic.list
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y kubelet=${k8sversion}-00 kubeadm=${k8sversion}-00 kubectl=${k8sversion}-00 cri-o-1.12 cri-o-runc containernetworking-plugins || true
apt install -yf
apt-mark hold kubelet kubeadm kubectl

# Load br_netfilter kernel module
echo 'br_netfilter' >> /etc/modules-load.d/br_netfilter.conf
modprobe br_netfilter

# Configure sysctl
cat <<'EOF' >> /etc/sysctl.conf
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF
sysctl -p

# Configure and start crio
sed -i '/^cgroup_manager/s/systemd/cgroupfs/' /etc/crio/crio.conf
systemctl enable crio
systemctl start crio

# Point kubelet at big ephemeral drive
mkdir /mnt/kubelet
echo 'KUBELET_EXTRA_ARGS="--root-dir=/mnt/kubelet --cloud-provider=aws"' > /etc/default/kubelet

# Join the cluster
for i in {1..50}; do kubeadm join --cri-socket=/var/run/crio/crio.sock --token=${k8stoken} --discovery-token-unsafe-skip-ca-verification --node-name=$(hostname -f) ${masterIP}:6443 && break || sleep 15; done
