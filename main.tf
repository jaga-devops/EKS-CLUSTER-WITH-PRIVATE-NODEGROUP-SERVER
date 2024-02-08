provider "aws" {
      region     = "${var.region}"
      access_key = "${var.access_key}"
      secret_key = "${var.secret_key}"
}

#CREATING 1 VPC
resource "aws_vpc" "main" {
  cidr_block = var.cidr_block
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "OWN-VPC"
  }
}

#CREATE PUBLIC SUBNET1
resource "aws_subnet" "public1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.public_subnet1_cidr_block
  availability_zone = "us-east-2a"
  map_public_ip_on_launch = true #THIS WILL ENABLE PUBLIC IP OF INSTANCE WHICH WILL BECREATED IN PUBLIC SUBNET
  tags = {
    Name = "PUBLIC-SUBNET-1"
  }
}

#CREATE PUBLIC SUBNET2
resource "aws_subnet" "public2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.public_subnet2_cidr_block
  map_public_ip_on_launch = true #THIS WILL ENABLE PUBLIC IP OF INSTANCE WHICH WILL BECREATED IN PUBLIC SUBNET
  availability_zone = "us-east-2b"
  tags = {
    Name = "PUBLIC-SUBNET-2"
  }
}

#CREATE PUBLIC SUBNET3
resource "aws_subnet" "public3" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.public_subnet3_cidr_block
  map_public_ip_on_launch = true #THIS WILL ENABLE PUBLIC IP OF INSTANCE WHICH WILL BECREATED IN PUBLIC SUBNET
  availability_zone = "us-east-2c"
  tags = {
    Name = "PUBLIC-SUBNET-3"
  }
}
#CREATE PRIVATE SUBNET1
resource "aws_subnet" "private1" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.private_subnet1_cidr_block
  availability_zone = "us-east-2a"

  tags = {
    Name = "PRIVATE-SUBNET-1"
  }
}

#CREATE PRIVATE SUBNET2
resource "aws_subnet" "private2" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.private_subnet2_cidr_block
  availability_zone = "us-east-2b"

  tags = {
    Name = "PRIVATE-SUBNET-2"
  }
}

#CREATE PRIVATE SUBNET3
resource "aws_subnet" "private3" {
  vpc_id     = aws_vpc.main.id
  cidr_block = var.private_subnet3_cidr_block
  availability_zone = "us-east-2c"

  tags = {
    Name = "PRIVATE-SUBNET-3"
  }
}

#CREATE INTERNET GATEWAY
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "OWN-main"
  }
}

#CREATING ELASTIC IP WHICH WILL BW ASSOCIATED WITH NAT GATEWAY
resource "aws_eip" "EIP1" {
  tags = {
    Env = "dev"
  }
}

#CREATE NAT GATEWAY IN PUBLIC SUBNET 
resource "aws_nat_gateway" "example" {
  allocation_id = aws_eip.EIP1.id #NATGATEWAY SHOULD HAVE ELASTIC IP
  subnet_id     = aws_subnet.public1.id #VVIMP IT's ALWAYS RECOMMENDED THAT NAT GATEWAY SHOULD BE CREATED IN PUBLIC SUBNET

  tags = {
    Name = "gw NAT"
  }

  # To ensure proper ordering, it is recommended to add an explicit dependency
  # on the Internet Gateway for the VPC.
  depends_on = [aws_internet_gateway.gw]
}

#CREATING PUBLIC ROUTE TABLE
resource "aws_route_table" "publicRT" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "PUBLIC-RT-1"
  }
}

#CREATING ROUTE FOR PUBLIC ROUTE TABLE
resource "aws_route" "public" {
  route_table_id         = aws_route_table.publicRT.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.gw.id
}

#SUBNET ASSOCIATE WITH ROUTE OF PUBLIC ROUTE TABLE
resource "aws_route_table_association" "public1" {
  subnet_id      = aws_subnet.public1.id
  route_table_id = aws_route_table.publicRT.id
}

#SUBNET ASSOCIATE WITH ROUTE OF PUBLIC ROUTE TABLE
resource "aws_route_table_association" "public2" {
  subnet_id      = aws_subnet.public2.id
  route_table_id = aws_route_table.publicRT.id
}

#SUBNET ASSOCIATE WITH ROUTE OF PUBLIC ROUTE TABLE
resource "aws_route_table_association" "public3" {
  subnet_id      = aws_subnet.public3.id
  route_table_id = aws_route_table.publicRT.id
}
#CREATING PRIVATE ROUTE TABLE
resource "aws_route_table" "privateRT" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "PRIVATE-RT-1"
  }
}

#CREATING ROUTE FOR PRIVATE ROUTE TABLE
resource "aws_route" "private" {
  route_table_id         = aws_route_table.privateRT.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id             = aws_nat_gateway.example.id
}

#SUBNET ASSOCIATE WITH ROUTE OF PRIVATE  ROUTE TABLE
resource "aws_route_table_association" "private1" {
  subnet_id      = aws_subnet.private1.id
  route_table_id = aws_route_table.privateRT.id
}

#SUBNET ASSOCIATE WITH ROUTE OF PRIVATE  ROUTE TABLE
resource "aws_route_table_association" "private2" {
  subnet_id      = aws_subnet.private2.id
  route_table_id = aws_route_table.privateRT.id
}

#SUBNET ASSOCIATE WITH ROUTE OF PRIVATE  ROUTE TABLE
resource "aws_route_table_association" "private3" {
  subnet_id      = aws_subnet.private3.id
  route_table_id = aws_route_table.privateRT.id
}

#CREATING VPN-SG

resource "aws_security_group" "VPN-SG" {
  name        = "VPN_SG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  ingress {
    description      = "TLS from VPC"
    from_port        = 19909
    to_port          = 19909
    protocol         = "udp"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  ingress {
    description      = "TLS from VPC"
    from_port        = 27017
    to_port          = 27017
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }


  ingress {
    description      = "TLS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "VPN SECURITY GROUP"
  }
}

#CREATE BASTION HOST SG

resource "aws_security_group" "BASTION-HOST-SG" {
  name        = "BASTION-HOST-SG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id
  tags = {
    Name = "BASTION HOST SECURITY GROUP"
  }
}


#ADDING INBOUND RULE FOR BASTION HOST SECURITY GROUP
resource "aws_security_group_rule" "BASTION-HOST-SG-RULE" {
  security_group_id = aws_security_group.BASTION-HOST-SG.id
  type              = "ingress"
  from_port        = 22
  to_port          = 22
  protocol         = "tcp"
  source_security_group_id = aws_security_group.VPN-SG.id
}

#ADDING OUTBOUND RULE FOR BASTION HOST SECURITY GROUP
resource "aws_security_group_rule" "BASTION-HOST-SG-OUTBOUND-RULE" {
  security_group_id = aws_security_group.BASTION-HOST-SG.id
  type              = "egress"
  from_port        = 0
  to_port          = 0
  protocol         = "-1"
  cidr_blocks      = ["0.0.0.0/0"]
}
#CREATING PROD ELEVATE NGINX SG
resource "aws_security_group" "PROD-ELEVATE-NGINX-SG" {
  name        = "PROD_ELEVATE_NGINX_SG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  ingress {
    description      = "TLS from VPC"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  ingress {
    description      = "TLS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "PROD ELEVATE NGINX SECURITY GROUP"
  }
}
#CREATING HASHICROP VAULT SG
resource "aws_security_group" "HASHICROP-VAULT-SG" {
  name        = "HASHICROP_VAULT_SG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  ingress {
    description      = "TLS from VPC"
    from_port        = 8200
    to_port          = 8200
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "HASHICROP VAULT SECURITY GROUP"
  }
}
#CREATING PROD ELEVATE ANALYTICS SG
resource "aws_security_group" "PROD-ELEVATE-ANALYTICS-SG" {
  name        = "PROD_ELEVATE_ANALYTICS_SG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }


  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "PRO ELEVATE ANALYTICS SECURITY GROUP"
  }
}

#CREATING PROD ELEVATE BIGBLUE BUTTON SG
resource "aws_security_group" "PROD-ELEVATE-BIGBLUE-BUTTON-SG" {
  name        = "PROD_ELEVATE_BIGBLUE_BUTTON_SG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  ingress {
    description      = "TLS from VPC"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  ingress {
    description      = "TLS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  ingress {
    description      = "TLS from VPC"
    from_port        = 16384
    to_port          = 32768
    protocol         = "udp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "PROD ELEVATE BIGBLUE BUTTON SECURITY GROUP"
  }
}

#CREATING PROD ELEVATE DB 1 SG
resource "aws_security_group" "PROD-ELEVATE-DB-1-SG" {
  name        = "PROD_ELEVATE_DB_1_SG"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.main.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  ingress {
    description      = "TLS from VPC"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  ingress {
    description      = "TLS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  ingress {
    description      = "TLS from VPC"
    from_port        = 27017
    to_port          = 27017
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = " PROD ELEVATE DB 1 SECURITY GROUP"
  }
}

#CREATE BASTION HOST

resource "aws_instance" "bastion_host_server" {
  ami           = "ami-05fb0b8c1424f266b" # us-west-2
  instance_type = "t2.micro"
  key_name = "jaga-ohio"
  subnet_id = aws_subnet.private1.id
  vpc_security_group_ids = [aws_security_group.BASTION-HOST-SG.id]
  tags = {
    Name = "BASTION HOST"
  }
}

#CREATE PROD ELEVATE NGINX SERVER
resource "aws_instance" "PROD-ELEVATE-NGINX" {
  ami           = "ami-05fb0b8c1424f266b"# us-west-2
  instance_type = "t2.micro"
  key_name = "jaga-ohio"
  subnet_id = aws_subnet.private2.id
  vpc_security_group_ids = [aws_security_group.PROD-ELEVATE-NGINX-SG.id]
  tags = {
    Name = "PROD ELEVATE NGINX"
  }
}

#CREATE PROD ELEVATE ANALYTICS SERVER
resource "aws_instance" "PROD-ELEVATE-ANALYTICS" {
  ami           = "ami-05fb0b8c1424f266b" # us-west-2
  instance_type = "t2.micro"
  key_name = "jaga-ohio"
  subnet_id = aws_subnet.private3.id
  vpc_security_group_ids = [aws_security_group.PROD-ELEVATE-ANALYTICS-SG.id]
  tags = {
    Name = "PROD ELEVATE ANALYTICS"
  }
}

resource "aws_instance" "VPN" {
  ami           = "ami-05fb0b8c1424f266b" # us-west-2
  instance_type = "t2.micro"
  key_name = "jaga-ohio"
  subnet_id = aws_subnet.public1.id
  vpc_security_group_ids = [aws_security_group.VPN-SG.id]
  tags = {
    Name = "VPN"
  }
}

#CREATE PROD ELEVATE BIGBLUE BUTTON SERVER
resource "aws_instance" "PROD-ELEVATE-BIGBLUE-BUTTON" {
  ami           = "ami-05fb0b8c1424f266b" # us-west-2
  instance_type = "t2.micro"
  key_name = "jaga-ohio"
  subnet_id = aws_subnet.public2.id
  vpc_security_group_ids = [aws_security_group.PROD-ELEVATE-BIGBLUE-BUTTON-SG.id]
  tags = {
    Name = "PROD ELEVATE BIGBLUE BUTTON"
  }
}

#CREATE PROD ELEVATE DB 1 SERVER

resource "aws_instance" "PROD-ELEVATE-DB-1" {
  ami           = "ami-05fb0b8c1424f266b" # us-west-2
  instance_type = "t2.micro"
  key_name = "jaga-ohio"
  subnet_id = aws_subnet.public3.id
  vpc_security_group_ids = [aws_security_group.PROD-ELEVATE-DB-1-SG.id]
  tags = {
    Name = "PROD ELEVATE DB 1"
  }
}

#CREATINGROLE FOR EKS CLUSTER
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "dev-eks-cluster-role" {
  name               = "dev-eks-cluster-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy_attachment" "dev-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.dev-eks-cluster-role.name
}

# Optionally, enable Security Groups for Pods
# Reference: https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html
resource "aws_iam_role_policy_attachment" "dev-AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.dev-eks-cluster-role.name
}
resource "aws_eks_cluster" "dev-eks" {
  name     = "dev-eks"
  role_arn = aws_iam_role.dev-eks-cluster-role.arn

  vpc_config {
    subnet_ids = [aws_subnet.private1.id, aws_subnet.private2.id, aws_subnet.private3.id]
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.dev-AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.dev-AmazonEKSVPCResourceController,
  ]
}

output "endpoint" {
  value = aws_eks_cluster.dev-eks.endpoint
}

output "kubeconfig-certificate-authority-data" {
  value = aws_eks_cluster.dev-eks.certificate_authority[0].data
}
resource "aws_iam_role" "dev-eks-node-role" {
  name = "dev-eks-node-role"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "dev-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.dev-eks-node-role.name
}

resource "aws_iam_role_policy_attachment" "dev-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.dev-eks-node-role.name
}

resource "aws_iam_role_policy_attachment" "dev-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.dev-eks-node-role.name
}

#EKS-NODE-Groups

resource "aws_eks_node_group" "dev-eks_node_group" {
  cluster_name    = aws_eks_cluster.dev-eks.name
  node_group_name = "dev-eks_node_group"
  node_role_arn   = aws_iam_role.dev-eks-node-role.arn
  subnet_ids      = [aws_subnet.private1.id, aws_subnet.private2.id,  aws_subnet.private3.id]

  scaling_config {
    desired_size = 2
    max_size     = 4
    min_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.dev-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.dev-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.dev-AmazonEC2ContainerRegistryReadOnly,
  ]
}
#EKS Node Security Group

resource "aws_security_group" "eks_nodes-sg" {
  name        = "eks_nodes-sg"
  description = "Security group for all nodes in the cluster"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
