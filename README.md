# VPConnect

Small dockerized IPSec server with focus on supporting routing to dynamic resources, vpc peering and security.

Can also be used without IPSec as a Port Forward / iptables tunnel to dynamic resources based on DNS hostname.

## Overview

VPConnect is based on `alpine:3.10` linux and `strongswan:5.8.0`. The resulting image is less than 300mb in size. (About 100mb compressed in ECR).

The system will run just fine on a `t2.nano`/`t3.nano` in most use cases.
So if you run it as a reserved instance for 3 years it will cost you around $1,5/month (excluding data transfer costs).

In case of ec2 termination and similar ECS will spawn a new ec2 with the correct elastic IP.

However, it will only spawn 1 ec2 in 1 AZ. So for real high availability please spawn 2-3 services in different AZs.

But if you can survive 2-3 minutes downtime if the ec2 is terminated and the unlikely event of 1 AZ being down, you will survive with 1 instance.

Please refer to the examples below for example configurations.

## Features

- You can have a wide SA and limit accessed by iptables rules and/or SG ingress rules.
- Supports multiple left and right subnets per connection.
- Iptables rules can be based on hostname and will be automatically updated when IP of the resource changes.
- Masquerade specific subnets/ips/rules, allowing traffic to traverse VPC Peering connections to different regions/accounts.
- Supports port forwarding (DNAT).
- Supports disabling IPSec if you only want to use for port forward.
- Static interface and elastic IP that survives ec2 teardown and creation, allowing route entries that don't need to be changed when ec2 is rotated or updating/changing IP on service on the other end.
- Extensive logging of both the vpconnect service with warning and errors, charon logging, new INPUT and FORWARD connections and ec2 security and health logs to CloudWatch logs.
- ECS will automatically launch a new ec2 if the previous one fails, and attaches the correct network interface and eip.
- Docker based so you can easily try out new versions and easily roll-back to previous version.
- Good security, "bad" security, integrity and dh aglos/groups are not included in the minimal strongswan build (see below).
- PSKs encrypted by KMS.

## Note on instance types

Some instance types don't use the ethX naming schema for network interfaces and are probably not supported by the
attach / detach interface commands in the CF metadata.

The following instances are known to be working and/or not working. Other instance types have currently not been tested.

| Instance type | State |
|-|-|
| t3a | Working |
| t3 | Working |
| t2 | Working |
| c5 | Working |
| c4 | Working |
| m5a | Not working |
| m5 | Not working |
| m4 | Not working |

## Diagram

![Diagram](diagrams/vpconnect.png)

## Supported Configuration

| VPN Types |
|-|
| Subnet to Subnet |

---

| Security Associations |
|-|
| IKEv1 |
| IKEv2 |

---

| Authentication |
|-|
| PSK (Pre-Shared Key) |

---

| Encryption Algorithms |
|-|
| aes / aes128 (128 bit AES-CBC) |
| aes192 (192 bit AES-CBC) |
| aes256 (256 bit AES-CBC) |
| aes128ctr (128 bit AES-COUNTER) |
| aes192ctr (192 bit AES-COUNTER) |
| aes256ctr (256 bit AES-COUNTER) |
| aes128ccm8 / aes128ccm64 (128 bit AES-CCM with 64 bit ICV) |
| aes192ccm8 / aes192ccm64 (192 bit AES-CCM with 64 bit ICV) |
| aes256ccm8 / aes256ccm64 (256 bit AES-CCM with 64 bit ICV) |
| aes128ccm12 / aes128ccm96 (128 bit AES-CCM with 96 bit ICV) |
| aes192ccm12 / aes192ccm96 (192 bit AES-CCM with 96 bit ICV) |
| aes256ccm12 / aes256ccm96 (256 bit AES-CCM with 96 bit ICV) |
| aes128ccm16 / aes128ccm128 (128 bit AES-CCM with 128 bit ICV) |
| aes192ccm16 / aes192ccm128 (192 bit AES-CCM with 128 bit ICV) |
| aes256ccm16 / aes256ccm128 (256 bit AES-CCM with 128 bit ICV) |
| aes128gcm8 / aes128gcm64 (128 bit AES-GCM with 64 bit ICV) |
| aes192gcm8 / aes192gcm64 (192 bit AES-GCM with 64 bit ICV) |
| aes256gcm8 / aes256gcm64 (256 bit AES-GCM with 64 bit ICV) |
| aes128gcm12 / aes128gcm96 (128 bit AES-GCM with 96 bit ICV) |
| aes192gcm12 / aes192gcm96 (192 bit AES-GCM with 96 bit ICV) |
| aes256gcm12 / aes256gcm96 (256 bit AES-GCM with 96 bit ICV) |
| aes128gcm16 / aes128gcm128 (128 bit AES-GCM with 128 bit ICV) |
| aes192gcm16 / aes192gcm128 (192 bit AES-GCM with 128 bit ICV) |

---

| Integrity Algorithms |
|-|
| sha1 / sha (SHA1 HMAC) |
| aesxcbc (AES XCBC) |
| aescmac (AES CMAC) |
| sha256 / sha2_256 (SHA2_256_128 HMAC) |
| sha384 / sha2_384 (SHA2_384_192 HMAC) |
| sha512 / sha2_512 (SHA2_512_256 HMAC) |

---

| DH Groups |
|-|
| DH Group 5  (1536-bit regular group) |
| DH Group 14 (2048-bit regular group) |
| DH Group 15 (3072-bit regular group) |
| DH Group 16 (4096-bit regular group) |
| DH Group 17 (6144-bit regular group) |
| DH Group 18 (8192-bit regular group) |
| DH Group 19 (256-bit nist elliptic group) |
| DH Group 20 (384-bit nist elliptic group) |
| DH Group 21 (521-bit nist elliptic group) |
| DH Group 25 (192-bit nist elliptic group) |
| DH Group 26 (224-bit nist elliptic group) |
| DH Group 27 (224-bit brainpool elliptic group) |
| DH Group 28 (256-bit brainpool elliptic group) |
| DH Group 29 (384-bit brainpool elliptic group) |
| DH Group 30 (512-bit brainpool elliptic group) |

## Requirements

You will need to have the following dependencies installed to build and deploy VPConnect.

- docker [https://www.docker.com/](https://www.docker.com/)
- awscli [https://aws.amazon.com/cli/](https://aws.amazon.com/cli/)
- make

Docker is used when building the Go program, creating a new service and generating the CF template.  
AWS CLI is used when deploying to AWS.

### Environment variables (or variables passed to make)

| Variable | Description |
|-|-|
| TAGS | Tags that will be sent to CloudFormation. |
| REPO | The ECR repo to push the docker images to. |

## Creating a new service (VPN Server)

```bash
SERVICE=<NAME> make new
```

Creating a new service with tagged resources / CF Tags

```bash
SERVICE=<NAME> TAGS="MyTag1=Value1 MyTag2=Value2" make new
```

Where `<NAME>` is the name of the service you want to create. (example: `myservice` or `myservice-dev` etc).  

`<NAME>` must start with a letter and only contain alphanumeric and hyphens characters.

When a new service has been generated the following configuration file will have been generated.  

| Filename | Description |
|-|-|
| services/`<NAME>`/config.yaml | The main configuration file. Please edit this and not any CF template directly. |
| services/`<NAME>`/cf.yaml | The generated template. Will be automatically generated when deploying. |

The `config.yaml` will look like this:

```yaml
FriendlyName: ""
Name: testar-dev
Environment: ""
Region: ""
Network:
  VpcId: ""
  PrivateSubnetId: ""
  PublicSubnetId: ""
Ecs:
  InstanceType: t2.nano
  Memory: 384
  DockerImage: ""
  SshKeyName: ""
  KmsKeyArn: ""
  AlarmSnsArn: ""
Config:
  Connections:
  - Name: ""
    Type: subnet
    IkeVersion: 2
    PskEncrypted: ""
    Encryption: aes256
    Integrity: sha256
    DiffieHellman: modp2048
    IkeLifeTime: 10800
    IpsecLifeTime: 3600
    Local:
      Subnets: []
    Remotes: []
  Rules: []
  CheckInterval: 300
  NoIpsec: false
Debug: false
Ingress: []

```

### Config Parameters

| Name | Description | Default | Required |
| - | - | - | - |
| FriendlyName | Friendly name used in descriptions etc. Can be spaces, upper case letters and so on. | | Yes |
| Name | The name for the service, used in naming resources. Must be lower case alphanumeric characters. | | Yes |
| NoIpsec | If we should start in "No IPSec" mode, disabling IPSec and only running in Port Forward mode | false | No |
| Debug | If the vpconnect program should start in debug mode. Very noisy! | false | No |
| Network.VpcId | The VPC ID the service should be deployed to. | | Yes |
| Network.PrivateSubnetId | The Subnet ID for the private network interface (used monitoring/internally). Only 1 subnet is supported. | | Yes |
| Network.PublicSubnetId  | The Subnet ID for the public network interface. Must be a public subnet and be in the same AZ as the Private subnet. Only 1 subnet is supported. | | Yes |
| Ecs.InstanceType | The Instance Type to use for the ECS cluster. | t2.nano | No |
| Ecs.Memory | The amount of memory to reserve for the service. Should correspond to something valid depending on Instance Type. | 384 | No |
| Ecs.DockerImage | What repo and docker image to use for the service. | | Yes |
| Ecs.SshKeyName | What root key to launch the instance with. | | Yes |
| Ecs.KmsKeyArn | KMS Key ARN used to decrypt the PSK SSM Parameter. This Key must have been added with a Key policy for the whole AWS account. Otherwise the policy for allowing decrypt added by this services CF will not be enough to use it. Please see [https://amzn.to/2Ox81e0](https://amzn.to/2Ox81e0). Should be whole key ARN and not an alias | | Yes (If IPSec enabled) |
| Ecs.AlarmSnsArn | What SNS topic ARN to send any alarms to. | | Yes |
| Config.CheckInterval | The number of seconds between checking DNS addresses in rules. Should try and match DNS TTL of the entries. | 300 | No |
| Config.Connections | IPSec connections. All sub config is only required if IPsec is enabled | | Yes (If IPSec enabled) |
| Config.Connections.Name | The name of the connection. | | Yes |
| Config.Connections.Type | What kind of VPN service to setup. (Currently only subnet is supported) | subnet | No |
| Config.Connections.IkeVersion | The IKE version Charon should run as (Either 1 or 2)  | 2 | No |
| Config.Connections.PskEncrypted | The encrypted PSK value. Should be encrypted by the key specified in Ecs.KmsKeyArn. Otherwise decryption will fail. |  | Yes |
| Config.Connections.Local.Subnets | List of subnets on the left/local side. Write subnets with CIDR notation. (example 192.168.0.0/24). | | Yes |
| Config.Connections.Remotes.Name | Remote Name. | | Yes |
| Config.Connections.Remotes.Ip | Remote IP for the right side. | | Yes |
| Config.Connections.Remotes.Id | Remote ID for the right side. | Same as Remotes.Ip | No |
| Config.Connections.Remotes.Subnets | List of subnets on the right/remote side. Write subnets with CIDR notation. (example 192.168.0.0/24) | | Yes |
| Config.Connections.Encryption | The Encryption algorithm to use. | aes256 | No |
| Config.Connections.Integrity | The Integrity algorithm to use. | sha256 | No |
| Config.Connections.DiffieHellman | The Diffie Hellman group to use. | modp2048 | No |
| Config.Connections.IkeLifeTime | The IKE/Phase 1 lifetime in seconds. | 10800 | No |
| Config.Connections.IpsecLifeTime | The IPSec/Phase 2 lifetime in seconds. | 3600 | No |
| Config.Rules | List of iptables rules. | | Yes |
| Config.Rules.From | List of CIDR or hostnames. If /MASK is omitted it defaults to /32.. | | Yes |
| Config.Rules.To | LList of CIDR or hostnames. If /MASK is omitted it defaults to /32. | | Yes |
| Config.Rules.Ports | List of destination ports. Allowed values are `1-65535` or `-1`. If `-1` is specified all ports will be opened. | | Yes |
| Config.Rules.PortForward | Map of `destination-port: source-port`. For example `10443:443` would redirect `443` to `10443` on the destination. | | No |
| Config.Rules.Protocols | List of protocols to allow. Allowed values are `tcp`, `udp`, `icmp` and `all`. If `all` or `icmp` is specified `Rules.Ports` will be ignored. So please take care when using `all`. | | Yes |
| Config.Rules.Masq | If we should use Masquerading on the traffic between From and To. This is required if you want to pass the traffic through an AWS VPC Peering connection. Valid values are `true` or `false`. | false | No |
| Ingress | List of Ingress rules on public network interface. If IPSec is enabled all remote WAN IPs are opened on UDP/500 + 4500 automatically. Any local subnets/SGs that need to be able to use the VPN service needs to be added as well. For configuration please see [https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-ingress.html](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-ingress.html) | | No |

Fill in the empty values according to your specification before attempting to run later steps.

## Generating CF template (optional)

This is optional since it's always run when running `make deploy`.  
But can be good if you want to review the automatically generated CF file before deploying (code review, etc)

```bash
SERVICE=<NAME> make gen
```

## Deploying service through CF

```bash
SERVICE=<NAME> make deploy
```

## Base template used for generating CF

The base template is located in `./cf-template.yaml`.

## Changing default values for service creation

The defaults for when a service is created can be modified by changing the def map in
`service-gen/defaults.go`

## Changing / Building the Docker Image

Make the changes to the docker image you want to do.  
Making docker will also trigger `go-build`, `docker-build` and `docker-push`.

```bash
make docker
```

## Logging

The service does a lot of logging.  
Everything is logged to CloudWatch Logs under the following log groups.  
Base Path of all `vpconnect` services in CloudWatch logs are `/vpconnect/<NAME>/<LOG>` where `<LOG>`
is one of the following

| CW Log | File / Log |
|-|-|
| secure | /var/log/secure (from ec2) |
| dmesg | /var/log/dmesg (from ec2) |
| messages | /var/log/messages (from ec2) |
| docker | /var/log/docker (from ec2) |
| ecs-init | /var/log/ecs/ecs-init (from ec2) |
| ecs-agent | /var/log/ecs/agent (from ec2) |
| ecs-audit | /var/log/ecs/audit.log* (from ec2) |
| iptables | Logging New connections (from ec2) |
| charon | Charon log from strongswan (from docker via ec2 (mounted file)) |
| vpconnect | The vpconnect program logging (from awslogs docker driver) |

## Alarms

The service has the following CloudWatch Alarms, if an alarm in triggered it will be sent to the specified AlarmSns in the config file.

| Alarm | Threshold |
|-|-|
| CPU alarm | >90% |
| Memory alarm | >95% |
| Swap alarm | >50% |
| Disk alarm | >90% |
| ECS/EC2 health check | |

## Storing services

You should store the services file in a separate repo.  
This is why the `./services` folder is ignored by `.gitignore`, so just create a new repo inside the services directory and push/pull changes to your own private repo for that.

## Routing

You will probably need to add routes to your route tables if you're planning on allowing
traffic from AWS to the remote site. (Routing not needed for other way if you're using the Masquerade feature).

You simple just add a route for the specific CIDR to the eni created by CF. This eni will survive ec2 termination/recycles.

So in the case of failure the route table shouldn't have to be updated.

## Example 1 - Connecting remote site to AWS with AWS VPC peering

The following steps will explain how to set up the VPConnect service to connect
a remote site to AWS Account 1. And then through a AWS VPC Peering connection to
AWS Account 2.

Only traffic from remote site to `acc1-service1.example.com`, `acc1-service2.example.com` and `acc2-service.example.com` on `tcp/443` will be allowed. Due to the AWS VPC Peering connection to AWS Account 2 we will mask traffic going to `acc2-service.example.com`.

The services are behind internal load balancers, so their IPs can change at any time. This is why
we refer to them by hostname instead of IPs.

| Name | Value |
|-|-|
| Remote WAN 1 | 213.111.111.1 |
| Remote WAN 2 | 213.111.111.2 |
| Remote Local Subnet 1 | 192.168.100.0/24 |
| Remote Local Subnet 2 | 192.168.101.0/24 |
| AWS Account 1 Subnet | 10.100.0.0/24 |
| AWS Account 1 VPC ID | vpc-12345678 |
| AWS Account 1 Private Subnet | subnet-87654321 (only used for primary ec2 network interface) |
| AWS Account 1 Public Subnet | subnet-12345678 (the network interface actually used) |
| AWS Account 2 Subnet | 10.200.0.0/24 |
| acc1-service1.example.com | 10.100.0.10, 10.100.0.11 |
| acc1-service2.example.com | 10.100.0.20, 10.100.0.21, 10.100.0.22 |
| acc2-service1.example.com | 10.200.0.10, 10.200.0.11, 10.200.0.12 |

### Create the base template

```bash
SERVICE=myservice make new
```

### Encrypt the password using KMS

Encrypt the PSK you want to set using KMS. It will be referred to as `MYENCRYPTIONHASH` in the example below.

### Edit the config file

Edit the config file under `services/myservice/config.yaml` to fit your needs.  
Check the parameters above for what must be set and not.

See the following example config.

```yaml
FriendlyName: MyService
Name: myservice
Network:
  VpcId: vpc-12345678
  PrivateSubnetId: subnet-87654321
  PublicSubnetId: subnet-12345678

Ecs:
  InstanceType: t2.nano
  Memory: 384
  DockerImage: my.ecr.repo.com/vpconnect:my-image-tag
  SshKeyName: my-key
  KmsKeyArn: arn:aws:kms:MyRegion:MyAccountId:key/My-KmsKey-Id
  AlarmSnsArn: arn:aws:sns:MyRegion:MyAccountId:MySNS

Config:
  Connections:
    - Name: awsacc1
      Type: subnet
      IkeVersion: 2
      PskEncrypted: MYENCRYPTIONHASH
      Encryption: aes256
      Integrity: sha256
      DiffieHellman: modp2048
      IkeLifeTime: 10800
      IpsecLifeTime: 3600

      Local:
        Subnets: [ 10.100.0.0/24, 10.200.0.0/24 ]

      Remotes:
        - Name: primary
          Ip: 213.111.111.1
          Subnets: [ 192.168.100.0/24, 192.168.101.0/24 ]

        - Name: secondary
          Ip: 213.111.111.2
          Subnets: [ 192.168.100.0/24, 192.168.101.0/24 ]

  Rules:
    - From: [ 192.168.100.0/24, 192.168.101.0/24 ]
      To: [ acc1-service1.example.com, acc1-service2.example.com ]
      Ports: [ 443 ]
      Protocols: [ tcp ]
      Masq: false

    - From: [ 192.168.100.0/24, 192.168.101.0/24 ]
      To: [ acc2-service1.example.com ]
      Ports: [ 443 ]
      Protocols: [ tcp ]
      Masq: true

  CheckInterval: 300

Debug: false
```

### Deploy it

Deploy it, please be sure that you are logged in and have set the correct `AWS_DEFAULT_PROFILE` and `AWS_DEFAULT_REGION`.

```bash
SERVICE=myservice make deploy
```

You can see how the generated template looks like by checking out `services/<NAME>/cf.yaml`.

## Example 2 - Port Forwarding from hostname to hostname

The following steps will explain how to set up the VPConnect service
to allow port forwarding only between two specific hostname. One of them being a remote service
that needs to access something inside your AWS account.

For this we will also disable the IPSec engine, which allows us to have a much smaller config.

In the example we we have gotten a list of 5 IPs that the vendor will be using to connect to our service. Since they might add, remove or change the IPs we need to solve this dynamically in a smart away.

Since they don't provide any automatic way for us to do this, we will create an route53 entry for this.
We will call it `external-provider1.example.com`. And to this entry we will add their 5 IPs.

This way, when they change IP we can simple just update out Route53 entry and the VPConnect service will automatically update the rules accordingly.

The service our external provider wants to reach is an internal load balancer that is `lb1.example.com`. Since it's a load balancer it's IPs can change and we will therefor reference it by hostname as well.

The port the provider needs to access it `tcp/443`.

Please note that you need to specify both `PortForward` option and `Masq` option for this to work as intended.

### Create the base Port Forward template

```bash
SERVICE=myportforward make new
```

### Edit the Port Forward config file

Edit the config file under `services/myportforward/config.yaml` to fit your needs.  
Check the parameters above for what must be set and not.

See the following example config.

```yaml
FriendlyName: MyPortForward
Name: myportforward
Network:
  VpcId: vpc-12345678
  PrivateSubnetId: subnet-87654321
  PublicSubnetId: subnet-12345678

Ecs:
  InstanceType: t2.nano
  Memory: 384
  DockerImage: my.ecr.repo.com/vpconnect:my-image-tag
  SshKeyName: my-key
  AlarmSnsArn: arn:aws:sns:MyRegion:MyAccountId:MySNS

Config:
  NoIpsec: true
  Rules:
    - From: [ external-provider1.example.com ]
      To: [ lb1.example.com ]
      Ports: [ 443 ]
      PortForward:
        443: 443
      Protocols: [ tcp ]
      Masq: true

  CheckInterval: 300

Ingress:
  - CidrIp: "0.0.0.0/0" # Or scope it down to exact IP or base CIDR if provider is dynamic as in this case. The more exact you're the more secure it is. Even if iptables will deny traffic if not from the exact IPs.
    Description: Allow test on 443 and 444
    FromPort: 443
    ToPort: 443
    IpProtocol: tcp

Debug: false
```

### Deploy Port Forward

Deploy it, please be sure that you are logged in and have set the correct `AWS_DEFAULT_PROFILE` and `AWS_DEFAULT_REGION`.

```bash
SERVICE=myportforward make deploy
```

You can see how the generated template looks like by checking out `services/<NAME>/cf.yaml`.
