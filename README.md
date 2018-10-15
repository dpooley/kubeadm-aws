## Really cheap Kubernetes cluster on AWS with kubeadm

This repository contains a bunch of Bash and Terraform code which provisions what I believe to be the cheapest possible single master Kubernetes cluster on AWS. You can run a 1 master, 1 worker cluster for somewhere around $6 a month, or just the master node (which can also run pods) for around $3 a month.

To achieve this, it uses m1.small spot instances and the free ephemeral storage they come with instead of EBS volumes.

Current features:

* Automatic backup and recovery. So if your master gets terminated, when the replacement is provisioned by AWS it will pick up where the old one left off without you doing anything. 😁
* Completely automated provisioning through Terraform and Bash.
* Variables for many things including number of workers (requested through spot fleet) and EC2 instance type.
* [External DNS](https://github.com/kubernetes-incubator/external-dns) as a cheap ELB alternative.
* Persistent Volumes using GP2 storage on EBS.

**Please use the releases rather than pulling from master. Master may be untested at any given point in time.**
**This isn't designed for production (unless you're very brave) but I've found no stability issues so far for my personal development usage.**

### Run it!

1. [Install Terraform](https://www.terraform.io/intro/getting-started/install.html)
2. [Install](https://docs.aws.amazon.com/cli/latest/userguide/installing.html) and [Configure](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html) AWS CLI
3. Clone the repo
4. Change directory: `cd kubeadm-aws`
5. Generate token: `python -c 'import random; print "%0x.%0x" % (random.SystemRandom().getrandbits(3*8), random.SystemRandom().getrandbits(8*8))' > token.txt`
6. Make an SSH key on region set in `variables.tf`(ap-southeast-2 by default) from the AWS console.
7. Run terraform plan: `terraform plan -var k8s-ssh-key=<aws-ssh-key-name> -var k8stoken=$(cat token.txt) -var admin-cidr-blocks="<my-public-ip-address>/32"`
8. Build out infrastructure: `terraform apply -var k8s-ssh-key=<aws-ssh-key-name> -var k8stoken=$(cat token.txt) -var admin-cidr-blocks="<my-public-ip-address>/32"`
9. Wait for cluster to build, check `/var/log/cloud-init-output.log` on master for progress
10. SSH to K8S master and run something: `ssh ubuntu@$(terraform output master_dns) -i <aws-ssh-key-name>.pem kubectl get no`
11. Done!

Optional Variables:

* `worker-count` - How many worker nodes to request via Spot Fleet (1 by default)
* `region` - Which AWS region to use (ap-southeast-2 by default)
* `kubernetes-version` - Which Kubernetes/kubeadm version to install (1.12.1 by default)
* `master-instance-type` - Which EC2 instance type to use for the master node (m1.small by default)
* `master-spot-price` - The maximum spot bid for the master node ($0.01 by default)
* `worker-instance-type` - Which EC2 instance type to use for the worker nodes (m1.small by default)
* `worker-spot-price` - The maximum spot bid for worker nodes ($0.01 by default)
* `cluster-name` - Used for naming the created AWS resources (k8s by default)
* `backup-enabled` - Set to "0" to disable the automatic etcd backups (1 by default)
* `backup-cron-expression` - A cron expression to use for the automatic etcd backups (`*/15 * * * *` by default)
* `external-dns-enabled` - Set to "0" to disable the pre-requisites for ExternalDNS (1 by default)

### Contributing

Forked from cablespaghetti/kubeadm-aws:
I've written this as a personal project and will do my best to maintain it to a good standard, despite having very limited free time. I very much welcome contributions in the form of Pull Requests and Issues (for both bugs and feature requests).

### Note about the license

I am not associated with UPMC Enterprises, but because this project started off as a fork of their code I am required to leave their license in place. However this is still Open Source and so you are free to do more-or-less whatever you want with the contents of this repository.

