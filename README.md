## Table of contents
* [General info](#general-info)
* [Technologies](#technologies)
* [Setup](#setup)

## General info
Working assumptions:
* Setup is designed for a standalone AWS account

This project is designed to:
* Install AWS resources to store terraform state
* Configure cloudtrail, including these features:
  * all region trail
  * log file vailidation
  * include global events
  * trail encryption with a CMK key
  * trail bucket protected from public access
  * s3 access logged to access logging s3 bucket
  * integration with cloudwatch
* Configure 3 alarms
  * root account usage
  * login without mfa
  * unauthorised api call
* Python script to remove the default networking for a new account


## Proposed validation tools
* terraform validate (terraform)
* terraform plan (terraform)
* chekov (terraform)
* terraform-compliance (terraform)
* flake8 (python)
* bandit (python)
	
## Technologies
Project is created with:
* Terraform v1.0.8
* Python 3.8.0 
	
## Setup
To run this project:
* Install terraform (versions above) 
* Install python (versions above)
* Download this project
* Configure aws credentials file with access key and secret key for your aws account
* Run terraform apply in these directories (in this order):
```
$ cd terraform_state_bucket
$ terraform init
$ terraform validate
$ terraform plan
$ terraform apply
$ cd cloudtrail_cloudwatch_setup
$ terraform init
$ terraform validate
$ terraform plan
$ terraform apply
```
* Run the python script
```
$ python3 delete_default_vpc.py  
```
