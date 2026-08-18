# SecAudit AWS Lab (Phase 5)

Deploys a **deliberately vulnerable** EC2 instance + S3 bucket so SecAudit
has a realistic target to audit end-to-end. This is a portfolio/demo
environment only.

## What gets deployed
- EC2 `t3.micro` (Ubuntu 22.04) running vsftpd (anonymous+write enabled),
  telnetd, and an SSH daemon configured to permit root login and
  password auth.
- Security group exposing 21/22/23/445/3389 to either your IP or the
  world (see `allow_my_ip_only`).
- A public-read, unencrypted S3 bucket.
- Host firewall (ufw) disabled by the provisioning script.

## Usage
```bash
cd terraform/aws-lab
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: set my_ip to your current public IP/32

terraform init
terraform plan
terraform apply

# grab the target IP
terraform output target_public_ip

# from the SecAudit project root:
python main.py --remote <target_public_ip> --output json,html,txt \
  --outdir reports/lab/
```

## Tear down
```bash
terraform destroy
```
**Always destroy this stack when you're done.** It is intentionally
insecure and will accrue AWS costs (and risk) if left running.

## Safety notes
- Defaults to restricting access to your IP only (`allow_my_ip_only = true`).
  Only flip this to expose 0.0.0.0/0 briefly for a demo, and destroy
  immediately after.
- Use a dedicated/sandbox AWS account if possible, never a production
  account.
- Nothing here should be copied into real infrastructure - every
  resource exists specifically to be a bad example.
