

resource "aws_vpc" "devops" {
  cidr_block           = var.vpc_cidr_block
  instance_tenancy     = "default"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Environment = "core"
    Name        = "devops"
  }

  lifecycle {
    ignore_changes = [tags]
  }
}

resource "aws_default_security_group" "defaul" {
    vpc_id = aws_vpc.devops.id
}


resource "aws_subnet" "private" {
  for_each = {
    for subnet in local.private_nested_config : subnet.name => subnet
  }

  vpc_id                  = aws_vpc.devops.id
  cidr_block              = each.value.cidr_block
  availability_zone       = var.az[index(local.private_nested_config, each.value)]
  map_public_ip_on_launch = false

  tags = {
    Environment                       = "devops"
    Name                              = each.value.name
    "kubernetes.io/role/internal-elb" = 1
  }

  lifecycle {
    ignore_changes = [tags]
  }
}

resource "aws_subnet" "public" {
  for_each = {
    for subnet in local.public_nested_config : subnet.name => subnet
  }

  vpc_id                  = aws_vpc.devops.id
  cidr_block              = each.value.cidr_block
  availability_zone       = var.az[index(local.public_nested_config, each.value)]
  map_public_ip_on_launch = true

  tags = {
    Environment              = "devops"
    Name                     = each.value.name
    "kubernetes.io/role/elb" = 1
  }

  lifecycle {
    ignore_changes = [tags]
  }
}
  
  
resource "aws_eip" "nat" {
  for_each = {
    for subnet in local.public_nested_config : subnet.name => subnet
  }

  vpc = true

  tags = {
    Environment = "core"
    Name        = "eip-${each.value.name}"
  }
}

resource "aws_nat_gateway" "nat-gw" {
  for_each = {
    for subnet in local.public_nested_config : subnet.name => subnet
  }

  allocation_id = aws_eip.nat[each.value.name].id
  subnet_id     = aws_subnet.public[each.value.name].id

  tags = {
    Environment = "core"
    Name        = "nat-${each.value.name}"
  }
}
  
resource "aws_route_table" "private" {
  for_each = {
    for subnet in local.public_nested_config : subnet.name => subnet
  }

  vpc_id = aws_vpc.devops.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat-gw[each.value.name].id
  }

  tags = {
    Environment = "core"
    Name        = "rt-${each.value.name}"
  }
}

resource "aws_route_table_association" "private" {

  for_each = {
    for subnet in local.private_nested_config : subnet.name => subnet
  }

  subnet_id      = aws_subnet.private[each.value.name].id
  route_table_id = aws_route_table.private[each.value.associated_public_subnet].id
}

  
#### IGW ####
  
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.devops.id

  tags = {
    Environment = "core"
    Name        = "igw-security"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.devops.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Environment = "core"
    Name        = "rt-public-security"
  }
}

resource "aws_route_table_association" "public" {
  for_each = {
    for subnet in local.public_nested_config : subnet.name => subnet
  }

  subnet_id      = aws_subnet.public[each.value.name].id
  route_table_id = aws_route_table.public.id
}
  
#### EKS ####
  
resource "aws_eks_cluster" "devops" {
  name     = var.eks_cluster_name
  role_arn = aws_iam_role.eks.arn

  version  = "1.18"

  vpc_config {
    security_group_ids      = [aws_security_group.eks_cluster.id]
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = concat([var.authorized_source_ranges], [for n in aws_eip.nat : "${n.public_ip}/32"])
    subnet_ids              = concat([for s in aws_subnet.private : s.id], [for s in aws_subnet.public : s.id])
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
  # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
  depends_on = [
    aws_iam_role_policy_attachment.eks-AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.eks-AmazonEKSVPCResourceController,
    aws_iam_role_policy_attachment.eks-AmazonEKSServicePolicy
  ]

  tags = {
    Environment = "core"
  }
}

resource "aws_iam_role" "eks" {
  name = var.eks_cluster_name

  assume_role_policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Principal": {
            "Service": "eks.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
        }
    ]
}
  EOF
}

data "tls_certificate" "cert" {
  url = aws_eks_cluster.devops.identity[0].oidc[0].issuer
}
resource "aws_iam_openid_connect_provider" "openid" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.cert.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.devops.identity[0].oidc[0].issuer
}

resource "aws_iam_role_policy_attachment" "eks-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks.name
}

resource "aws_iam_role_policy_attachment" "eks-AmazonEKSServicePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
  role       = aws_iam_role.eks.name
}

# Enable Security Groups for Pods
resource "aws_iam_role_policy_attachment" "eks-AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eks.name
}

resource "aws_security_group" "eks_cluster" {
  name        = "${var.eks_cluster_name}/ControlPlaneSecurityGroup"
  description = "Communication between the control plane and worker nodegroups"
  vpc_id      = aws_vpc.devops.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.eks_cluster_name}/ControlPlaneSecurityGroup"
  }
}
resource "aws_security_group_rule" "cluster_inbound" {
  description              = "Allow unmanaged nodes to communicate with control plane (all ports)"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = aws_eks_cluster.devops.vpc_config[0].cluster_security_group_id
  source_security_group_id = aws_security_group.eks_nodes.id
  to_port                  = 0
  type                     = "ingress"
}
      
#### Node group ####
      
resource "aws_eks_node_group" "private" {
  cluster_name    = aws_eks_cluster.devops.name
  node_group_name = "private"
  node_role_arn   = aws_iam_role.node-group.arn
  subnet_ids      = [for s in aws_subnet.private : s.id]

  labels          = {
    "type" = "private"
  }

  instance_types = ["m5.xlarge"]

  scaling_config {
    desired_size = 2
    max_size     = 4
    min_size     = 2
  }

  # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
  # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
  depends_on = [
    aws_iam_role_policy_attachment.node-group-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.node-group-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.node-group-AmazonEC2ContainerRegistryReadOnly
  ]

  tags = {
    Environment = "core"
  }
}

resource "aws_eks_node_group" "public" {
  cluster_name    = aws_eks_cluster.devops.name
  node_group_name = "public"
  node_role_arn   = aws_iam_role.node-group.arn
  subnet_ids      = [for s in aws_subnet.public : s.id]

  labels          = {
    "type" = "public"
  }

  instance_types = ["t3.medium"]

  scaling_config {
    desired_size = 1
    max_size     = 3
    min_size     = 1
  }

  depends_on = [
    aws_iam_role_policy_attachment.node-group-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.node-group-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.node-group-AmazonEC2ContainerRegistryReadOnly,
  ]

  tags = {
    Environment = "core"
  }
}

resource "aws_iam_role" "node-group" {
  name = "eks-node-group-role-devops"

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

resource "aws_iam_role_policy_attachment" "node-group-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.node-group.name
}

resource "aws_iam_role_policy_attachment" "node-group-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.node-group.name
}

resource "aws_iam_role_policy_attachment" "node-group-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.node-group.name
}

resource "aws_iam_role_policy" "node-group-ClusterAutoscalerPolicy" {
  name = "eks-cluster-auto-scaler"
  role = aws_iam_role.node-group.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
            "autoscaling:DescribeAutoScalingGroups",
            "autoscaling:DescribeAutoScalingInstances",
            "autoscaling:DescribeLaunchConfigurations",
            "autoscaling:DescribeTags",
            "autoscaling:SetDesiredCapacity",
            "autoscaling:TerminateInstanceInAutoScalingGroup"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role_policy" "node-group-AmazonEKS_EBS_CSI_DriverPolicy" {
  name = "AmazonEKS_EBS_CSI_Driver_Policy"
  role = aws_iam_role.node-group.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
            "ec2:AttachVolume",
            "ec2:CreateSnapshot",
            "ec2:CreateTags",
            "ec2:CreateVolume",
            "ec2:DeleteSnapshot",
            "ec2:DeleteTags",
            "ec2:DeleteVolume",
            "ec2:DescribeAvailabilityZones",
            "ec2:DescribeInstances",
            "ec2:DescribeSnapshots",
            "ec2:DescribeTags",
            "ec2:DescribeVolumes",
            "ec2:DescribeVolumesModifications",
            "ec2:DetachVolume",
            "ec2:ModifyVolume"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "ebs-csi-controller" {
  name = "AmazonEKS_EBS_CSI_DriverRole"

  assume_role_policy = jsonencode({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": aws_iam_openid_connect_provider.openid.arn
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "${replace(aws_iam_openid_connect_provider.openid.url, "https://", "")}:sub": "system:serviceaccount:kube-system:ebs-csi-controller-sa"
                    }
                }
            }
        ]
    })
}

resource "aws_security_group" "eks_nodes" {
  name        = "${var.eks_cluster_name}/ClusterSharedNodeSecurityGroup"
  description = "Communication between all nodes in the cluster"
  vpc_id      = aws_vpc.devops.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    security_groups = [aws_eks_cluster.devops.vpc_config[0].cluster_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "${var.eks_cluster_name}/ClusterSharedNodeSecurityGroup"
    Environment = "core"
  }
}
