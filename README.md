# VPConnect

Small dockerized IPSec server with focus on supporting routing to dynamic resources, vpc peering and security.  
Therefor lots of older DH groups, encryption algorithms etc are not supported.

## Overview

VPConnect is based on `alpine:3.7` linux and `strongswan:5.7.1`.  
The resulting image is less than 300mb in size.

Strongswan and alpine version can in the future be updated by updating the Dockerfile accordingly.  
For current version of strongswan please see [https://www.strongswan.org/download.html](https://www.strongswan.org/download.html).

The system will run just fine on a `t3.nano` or `t2.nano` in most use cases.  
So if you run it as a reserved instance for 3 years it will cost you around $1,5/month.

Please refer to the Example at the bottom of this page for an step by step example of how to create a new VPN service.

## Features

- You can have a wide SA subnets and limit based on ingress SG as well as iptable rules.
- Iptable rules can be based on DNS hostnames and will be automatically updated when changed.
- Rules can be based on From, To, Ports and Protocol.
- Masquerade specific rules, allowing traffic to traverse VPC Peering connections etc.
- Static interface and elastic IP that survives ec2 teardown and creation, allowing robust VPN service without changing route table.
- Extensive logging of both the service, charon log, new INPUT and FORWARD connections and ec2 security and health logs to CloudWatch logs.
- Automatically launch a new ec2 if the previous one fails, and attaches the correct network interface and eip.
- Docker based so you can easily try out new versions and easily roll-back to previous version.
- Good security, "bad" algos are not included in the minimal strongswan build (see below).
- Encrypts PSK password in global region using KMS. So PSK not stored anywhere in clear text (will be stored in clear text in china).

## Note on instance types (m)

Some instance types as the m class can have network interface names other than ethX.  
For now these will not work since the system relies on that the naming is eth0 for the primary and eth1 for the secondary.  
You're most welcome to add a pull request for this if needed.

## Diagram

![Diagram](diagrams/vpconnect.png)

## Supported Configuration

```text
VPN Types
[x] Subnet-2-Subnet
[ ] Virtual Network

Security Associations
[x] IKEv1
[x] IKEv2

Authentication
[ ] Public Key Authentication (Certificates)
[x] PSK (Pre-Shared Key)
[ ] EAP (Extensible Authentication Protocol)
[ ] XAuth (eXtended Authentication)

Encryption Algorithms
[ ] 3des (168 bit 3DES-EDE-CBC)
[ ] cast128 (128 bit CAST-CBC)
[ ] blowfish128 / blowfish (128 bit Blowfish-CBC)
[ ] blowfish192 (192 bit Blowfish-CBC)
[ ] blowfish256 (256 bit Blowfish-CBC)
[ ] null (Null encryption)
[x] aes / aes128 (128 bit AES-CBC)
[x] aes192 (192 bit AES-CBC)
[x] aes256 (256 bit AES-CBC)
[x] aes128ctr (128 bit AES-COUNTER)
[x] aes192ctr (192 bit AES-COUNTER)
[x] aes256ctr (256 bit AES-COUNTER)
[x] aes128ccm8 / aes128ccm64 (128 bit AES-CCM with 64 bit ICV)
[x] aes192ccm8 / aes192ccm64 (192 bit AES-CCM with 64 bit ICV)
[x] aes256ccm8 / aes256ccm64 (256 bit AES-CCM with 64 bit ICV)
[x] aes128ccm12 / aes128ccm96 (128 bit AES-CCM with 96 bit ICV)
[x] aes192ccm12 / aes192ccm96 (192 bit AES-CCM with 96 bit ICV)
[x] aes256ccm12 / aes256ccm96 (256 bit AES-CCM with 96 bit ICV)
[x] aes128ccm16 / aes128ccm128 (128 bit AES-CCM with 128 bit ICV)
[x] aes192ccm16 / aes192ccm128 (192 bit AES-CCM with 128 bit ICV)
[x] aes256ccm16 / aes256ccm128 (256 bit AES-CCM with 128 bit ICV)
[x] aes128gcm8 / aes128gcm64 (128 bit AES-GCM with 64 bit ICV)
[x] aes192gcm8 / aes192gcm64 (192 bit AES-GCM with 64 bit ICV)
[x] aes256gcm8 / aes256gcm64 (256 bit AES-GCM with 64 bit ICV)
[x] aes128gcm12 / aes128gcm96 (128 bit AES-GCM with 96 bit ICV)
[x] aes192gcm12 / aes192gcm96 (192 bit AES-GCM with 96 bit ICV)
[x] aes256gcm12 / aes256gcm96 (256 bit AES-GCM with 96 bit ICV)
[x] aes128gcm16 / aes128gcm128 (128 bit AES-GCM with 128 bit ICV)
[x] aes192gcm16 / aes192gcm128 (192 bit AES-GCM with 128 bit ICV)
[ ] aes128gmac (Null encryption with 128 bit AES-GMAC)
[ ] aes192gmac (Null encryption with 192 bit AES-GMAC)
[ ] aes256gmac (Null encryption with 256 bit AES-GMAC)
[ ] camellia128 / camellia (128 bit Camellia-CBC)
[ ] camellia192 (192 bit Camellia-CBC)
[ ] camellia256 (256 bit Camellia-CBC)
[ ] camellia128ctr (128 bit Camellia-COUNTER)
[ ] camellia192ctr (192 bit Camellia-COUNTER)
[ ] camellia256ctr (256 bit Camellia-COUNTER)
[ ] camellia128ccm8 / camellia128ccm64 (128 bit Camellia-CCM with 64 bit ICV)
[ ] camellia192ccm8 / camellia192ccm64 (192 bit Camellia-CCM with 64 bit ICV)
[ ] camellia256ccm8 / camellia256ccm64 (256 bit Camellia-CCM with 64 bit ICV)
[ ] camellia128ccm12 / camellia128ccm96 (128 bit Camellia-CCM with 96 bit ICV)
[ ] camellia192ccm12 / camellia192ccm96 (192 bit Camellia-CCM with 96 bit ICV)
[ ] camellia256ccm12 / camellia256ccm96 (256 bit Camellia-CCM with 96 bit ICV)
[ ] camellia128ccm16 / camellia128ccm128 (128 bit Camellia-CCM with 128 bit ICV)
[ ] camellia192ccm16 / camellia192ccm128 (192 bit Camellia-CCM with 128 bit ICV)
[ ] camellia256ccm16 / camellia256ccm128 (256 bit Camellia-CCM with 128 bit ICV)
[ ] chacha20poly1305 (256 bit ChaCha20/Poly1305 with 128 bit ICV)

Integrity Algorithms
[ ] md5 (MD5 HMAC)
[ ] md5_128 (MD5_128 HMAC)
[x] sha1 / sha (SHA1 HMAC)
[ ] sha1_160 (SHA1_160 HMAC)
[x] aesxcbc (AES XCBC)
[x] aescmac (AES CMAC)
[ ] aes128gmac (128-bit AES-GMAC)
[ ] aes192gmac (192-bit AES-GMAC)
[ ] aes256gmac (256-bit AES-GMAC)
[x] sha256 / sha2_256 (SHA2_256_128 HMAC)
[x] sha384 / sha2_384 (SHA2_384_192 HMAC)
[x] sha512 / sha2_512 (SHA2_512_256 HMAC)
[ ] sha256_96 / sha2_256_96 (SHA2_256_96 HMAC)

DH Groups
[ ] DH Group 1  (768-bit regular group)
[ ] DH Group 2  (1024-bit regular group)
[x] DH Group 5  (1536-bit regular group)
[x] DH Group 14 (2048-bit regular group)
[x] DH Group 15 (3072-bit regular group)
[x] DH Group 16 (4096-bit regular group)
[x] DH Group 17 (6144-bit regular group)
[x] DH Group 18 (8192-bit regular group)
[x] DH Group 19 (256-bit nist elliptic group)
[x] DH Group 20 (384-bit nist elliptic group)
[x] DH Group 21 (521-bit nist elliptic group)
[ ] DH Group 22 (1024-bit modulo prime group)
[ ] DH Group 23 (2048-bit modulo prime group)
[ ] DH Group 24 (2047-bit modulo prime group)
[x] DH Group 25 (192-bit nist elliptic group)
[x] DH Group 26 (224-bit nist elliptic group)
[x] DH Group 27 (224-bit brainpool elliptic group)
[x] DH Group 28 (256-bit brainpool elliptic group)
[x] DH Group 29 (384-bit brainpool elliptic group)
[x] DH Group 30 (512-bit brainpool elliptic group)
[ ] DH Group 31 (256-bit elliptic curve25519/x25519)
```

## Requirements

You will need to have the following dependencies installed to build and deploy VPConnect.

- docker [https://www.docker.com/](https://www.docker.com/)
- awscli [https://aws.amazon.com/cli/](https://aws.amazon.com/cli/)

Docker is used when building the Go program, creating a new service and generating the CF template.  
AWS CLI is used when deploying to AWS.

### Necessary Environment variables (or variables passed to make)

```text
AWS_PROFILE   The AWS profile to use for deploying the service as well as pushing the docker image.
AWS_REGION    The AWS Region to deploy the service and where ECR is located, eg. "eu-west-1".
OWNER         The OWNER of the service, this is just used for tagging purposes.
REPO          The ECR repo to push the docker images to. This is only required when building the docker image.
```

## Creating a new service (VPN Server)

```bash
make new SERVICE=<NAME> ENVIRONMENT=<ENV> REGION=<REGION>
```

Where `<NAME>` is the name of the service you want to create. (example: `myservice`).  
`<ENV>` is the environment of the service. (example: `prod`).  
And `<REGION>` is either global or china, this because the template and setup differs between
global and china, due to the lack of KMS support in china region.

Both `<NAME>` and `<ENV>` should only contain `lower case alphanumeric` characters as well as `"-"` characters.  
`<REGION>` can be either lower case or upper case.

When a new service has been generated the following configuration file will have been generated.  

```text
services/<NAME>-<ENV>/config.yaml       The main configuration file. Please edit this and not any CF template directly.
```

The file will look similar to this

```yaml
FriendlyName: ""
Name: myservice
Environment: prod
Region: global
Network:
  VpcId: ""
  PrivateSubnetId: ""
  PublicSubnetId: ""
Ecs:
  InstanceType: t3.nano
  Memory: 384
  DockerImage: ""
  SshKeyName: ""
  KmsKeyArn: ""
  AlarmSnsArn: ""
  AmiImageId: ""
Vpn:
  Type: subnet
  IkeVersion: 2
  PskEncrypted: ""
  Psk: ""
  CheckInterval: 300
  LocalSubnets: []
  RemoteSubnets: []
  RemoteIps: []
  Encryption: aes256
  Integrity: sha256
  DiffieHellman: modp2048
  IkeLifeTime: 10800
  IpsecLifeTime: 3600
  CharonLogLevel: 1
Debug: false
Rules: []
Ingress: []
```

### Config Parameters

```text
| Var name                | Description                                                      | Default value | Required |
|=========================|==================================================================|===============|==========|
| FriendlyName            | Friendly name used in descriptions etc.                          |               | Yes      |
|                         | Can be spaces, upper case letters and so on.                     |               |          |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Name                    | The name for the service, used in naming resources.              |               | Yes      |
|                         | Must be lower case alphanumeric characters.                      |               |          |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Environment             | The environment it's deployed to. prod, staging, test, dev etc.  |               | Yes      |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Region                  | Either global or china.                                          |               | Yes      |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Network.VpcId           | The VPC ID the service should be deployed to.                    |               | Yes      |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Network.PrivateSubnetId | The Subnet ID for the private network interface                  |               | Yes      |
|                         | (used monitoring/internally). Only 1 subnet is supported.        |               |          |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Network.PublicSubnetId  | The Subnet ID for the public network interface.                  |               | Yes      |
|                         | Must be a public subnet and be in the same AZ as the             |               |          |
|                         | Private subnet. Only 1 subnet is supported.                      |               |          |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Ecs.InstanceType        | The Instance Type to use for the ECS cluster.                    | t3/t2.nano    | No       |
|                         | t3.nano default for global, t2.nano for china.                   |               |          |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Ecs.Memory              | The amount of memory to reserve for the service.                 | 384           | No       |
|                         | Should correspond to something valid depending on Instance Type. |               |          |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Ecs.DockerImage         | What repo and docker image to use for the service.               |               | Yes      |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Ecs.SshKeyName          | What root key to launch the instance with.                       |               | Yes      |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Ecs.KmsKeyArn           | KMS Key ARN used to decrypt the PSK SSM Parameter.               |               | Yes for  |
|                         | This Key must have been added with a Key policy for the whole    |               | global   |
|                         | AWS account. Otherwise the policy for allowing decrypt added     |               |          |
|                         | by this services CF will not be enough to use it. Please see     |               |          |
|                         | https://amzn.to/2Ox81e0                                          |               |          |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Ecs.AlarmSnsArn         | What SNS topic ARN to send any alarms to.                        |               | Yes      |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Ecs.AmiImageId          | What AMI Image ID to use for instances.                          |               | Yes for  |
|                         | This setting will be ignored if region is global.                |               | china    |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.Type                | What kind of VPN service to setup.                               | subnet        | No       |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.IkeVersion          | The IKE version Charon should run as (Either 1 or 2)             | 2             | Yes      |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.PskEncrypted        | The encrypted PSK value. Should be encrypted by the key          |               | Yes for  |
|                         | specified in Ecs.KmsKeyArn. Otherwise decryption might fail      |               | global   |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.Psk                 | The unencrypted PSK value. Should only be used in china region.  |               | Yes for  |
|                         | This setting will be ignored if region is global.                |               | china    |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.CheckInterval       | The number of seconds between checking DNS addresses in rules.   | 300           | No       |
|                         | Should try and match DNS TTL of the entries.                     |               |          |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.LocalSubnets        | List of subnets on the left/local side.                          |               | Yes      |
|                         | Write subnets with CIDR notation. (example 192.168.0.0/24)       |               |          |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.RemoteSubnets       | List of subnets on the right/remote side.                        |               | Yes      |
|                         | Write subnets with CIDR notation. (example 192.168.0.0/24)       |               |          |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.RemoteIps           | Remote IPs for the right side. At least 1 must be specified      |               | Yes      |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.Encryption          | The Encryption algorithm to use.                                 | aes256        | No       |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.Integrity           | The Integrity algorithm to use.                                  | sha256        | No       |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.DiffieHellman       | The Diffie Hellman group to use.                                 | modp2048      | No       |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.IkeLifeTime         | The IKE/Phase 1 lifetime in seconds.                             | 10800         | No       |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.IpsecLifeTime       | The IPSec/Phase 2 lifetime in seconds.                           | 3600          | No       |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Vpn.CharonLogLevel      | The loglevel to use for charon.log. (Valid values 1-4).          | 1             | No       |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Debug                   | If the vpconnect program should start in debug mode- very noisy! | false         | No       |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Rules                   | List of rules (see rules below!)                                 |               | Yes      |
|-------------------------|------------------------------------------------------------------|---------------|----------|
| Ingress                 | Manual SG Ingress rule on the Public Interface.                  |               | No       |
|                         | Only the WAN IP (primary and secondary) are opened on            |               |          |
|                         | UDP/500 + 4500 automatically. Any local subnets/SGs that need    |               |          |
|                         | to be able to use the VPN service needs to be added as well.     |               |          |
|                         | (see ingress below)                                              |               |          |
|-------------------------|------------------------------------------------------------------|---------------|----------|
```

Fill in the empty values according to your specification before attempting to run later steps.

## Rules Configuration

Rules are used for creating iptables rules allowing traffic to and from left and right side.  
Per default everything is blocked, so if you have no rules it will not be possible to generate the cf file.
Because if rules are empty this service serves no purpose :)

```yaml
- From: [ "172.0.0.0/24", "host.hej.com" ]
  To: [ "192.168.1.0/24" ]
  Ports: [ 443, 8080 ]
  Protocols: [ "tcp" ]
  Masq: false
```

### Rules parameters

```text
From         List of CIDR or hostnames. If /MASK is omitted it defaults to /32.
To           List of CIDR or hostnames. If /MASK is omitted it defaults to /32.
Ports        List of ports to allow between From and To destinations.
             Allowed values are between 1 and 65535 and -1 for all ports.
Protocols    Protocols to allow. Valid values are tcp, udp, icmp and -1 (for all protocols).
Masq         If we should use Masquerading on the traffic between From and To.
             This is required if you want to pass the traffic through an AWS VPC Peering connection.
             Valid values are true or false. If omitted defaults to false.
             If set to true a POSTROUTING rule for masquerading the traffic will be added in addition
             to the normal FORWARD rule.
```

## Ingress Configuration

Ingress can be used to allow manual ingress rules on the public network interface security group.  
This is needed to allow local subnets to connect to/through the VPN tunnel as these are not added
automatically.

For possible parameters see SecurityGroupIngress CloudFormation YAML.  
All supported parameters from Amazon, such as using SecurityGroup, Network ranges etc are supported.

[https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-ingress.html](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-ec2-security-group-ingress.html)

## Generating CF template (optional)

This is optional in the sense that this step is always run when running `make deploy`.  
But can be good if you want to review the automatically generated CF file before deploying (code review, etc)

```bash
make gen SERVICE=<NAME> ENVIRONMENT=<ENV>
```

## Deploying service

```bash
make deploy SERVICE=<NAME> ENVIRONMENT=<ENV>
```

## Base template used for generating CF

The base template is located in `cf-template.yaml` for global.  
And `cf-template-cn.yaml` for china.

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

The service does a lot of logging. Everything is logged to cloudwatch under the following log groups.  
Base Path of all `vpconnect` services in CloudWatch logs are `/vpconnect/<NAME>-<ENV>/<LOG>` where `<LOG>`
is one of the following

```text
secure        /var/log/secure (from ec2)
dmesg         /var/log/dmesg (from ec2)
messages      /var/log/messages (from ec2)
docker        /var/log/docker (from ec2)
ecs-init      /var/log/ecs/ecs-init (from ec2)
ecs-agent     /var/log/ecs/agent (from ec2)
ecs-audit     /var/log/ecs/audit.log* (from ec2)
iptables      Logging New connections (from ec2)
charon        Charon log from strongswan (from docker via ec2 (mounted file))
vpconnect     The vpconnect program logging (from awslogs docker driver)
```

## Alarms

The service has the following CloudWatch Alarms, if an alarm in triggered it will be sent to the specified AlarmSns in the config file.

```text
CPU alarm        >90%
Memory alarm     >95%
Swap alarm       >50%
Disk alarm       >90%
EC2 Health Check alarm
```

## Storing services

You should store the services file in a separate repo.  
For this the services folder is ignored by gitignore, so just create a new repo inside the services file
and push/pull changes to your own private repo for that.

## Routing

You will probably need to add routes to your route tables if you're planning on allowing
traffic from AWS to the remote site. (Routing not needed for other way if you're using the Masquerade option).

You simple just add a route for the specific CIDR to the eni created. This eni will survive ec2 termination/recycle.

## Example (step-by-step)

The following steps will explain how to generate a new VPConnect service.

### Create the base template

```bash
make new SERVICE=test ENVIRONMENT=dev REGION=global
```

### Edit the config file

Edit the config file under `services/test-dev/config.yaml` to fit your needs.  
Check the parameters above for what must be set and not.

See the following example config.

```yaml
FriendlyName: "TEST"
Name: "test"
Environment: "dev"
Region: "global"
Network:
  VpcId: "vpc-12345678"
  PrivateSubnetId: "vpc-87654321"
  PublicSubnetId: "vpc-12345678"


Ecs:
  InstanceType: "t3.nano"
  Memory: 384
  DockerImage: "my.ecr.repo.com/vpconnect:my-image-tag"
  SshKeyName: "my-private-key"
  KmsKeyArn: "arn:aws:kms:MyRegion:MyAccountId:key/My-Key-Id" (leave empty if in china)
  AlarmSnsArn: "arn:aws:sns:MyRegion:MyAccountId:MySNS"
  AmiImageId: "AmiImageID" (leave empty if in global)

Vpn:
  Type: "subnet"
  IkeVersion: 2
  PskEncrypted: "EncryptedString" (leave empty if in china)
  Psk: "Psk Unencrypted" (leave empty if in global)
  CheckInterval: 300
  LocalSubnets:
    - "10.0.0.0/24"
  RemoteSubnets:
    - "192.168.0.0/24"
    - "192.168.1.0/24"
  RemoteIps:
    - "123.123.123.123"
  Encryption: "aes256"
  Integrity: "sha256"
  DiffieHellman: "modp2048"
  IkeLifeTime: 10800
  IpsecLifeTime: 3600
  CharonLogLevel: 1

Debug: false

# Allow traffic from our side, 10.0.0.0/24 to 192.168.0.0/24 and
# 192.168.1.0/24. But for 192.168.0.0/24 only allow TCP 443 and 444
# but allow all protocols and ports to 192.168.1.0/24 but hide it
# behind NAT.
# But only for port tcp 443 and 444. This will go to the security
# group rules. So in the security group we allow all protocols and ports
# from 10.0.0.0/24.
# And in the rules section below we limit the allowed traffic further.
# These rules will make it possible for 10.0.0.0/24 to contact any
# host on 192.168.0.0/24 network on port tcp/443 and 443.
# And allows all traffic from 10.0.0.0/24 to 192.168.1.0/24 on any port.
# However all traffic from 192.168.0.0/24 or 192.168.1.0/24 to our
# network 10.0.0.0/24 will be blocked my iptable rules.
Ingress:
  - CidrIp: "10.0.0.0/24"
    Description: Allow test on 443 and 444
    FromPort: -1
    ToPort: -1
    IpProtocol: -1

Rules:
  - From: [ "10.0.0.0/24" ]
    To: [ "192.168.0.0/24" ]
    Ports: [ 443, 444 ]
    Protocols: [ "tcp" ]
    Masq: false

  - From: [ "10.0.0.0/24" ]
    To: [ "192.168.1.0/24" ]
    Ports: [ -1 ]
    Protocols: [ "-1" ]
    Masq: true
```

### Deploy it

Deploy it, please be sure that you are authed and have the correct AWS_PROFILE set.

```bash
make deploy SERVICE=test ENVIRONMENT=dev
```

You can see how the generated template looks like by checking out `services/<NAME>-<ENV>/cf.yaml`.