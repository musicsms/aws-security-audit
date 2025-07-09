# AWS Security Audit Report

## Report Information

- **Account ID**: 001979122433
- **Security Profile**: CIS AWS Foundations Benchmark (1.4.0)
- **Generated**: 2025-07-09T10:21:02.930362Z
- **Generator**: AWS Security Audit Tool v1.0.0

## Executive Summary

- **Total Checks**: 124
- **Pass Rate**: 21.77%
- **Critical Failures**: 0
- **High Severity Failures**: 0
- **Regions Audited**: 
- **Services Audited**: RDS.1, KMS.2, EC2.1, RDS.3, EC2.4, VPC.1, VPC.2, KMS.1, RDS.2

## Results by Status

| Status | Count | Percentage |
|--------|-------|------------|
| OK | 27 | 21.8% |
| NOK | 0 | 0.0% |
| NEED_REVIEW | 40 | 32.3% |
| ERROR | 57 | 46.0% |


## Results by Severity

| Severity | Count | Percentage |
|----------|-------|------------|
| critical | 4 | 3.2% |
| high | 58 | 46.8% |
| medium | 60 | 48.4% |
| low | 2 | 1.6% |
| info | 0 | 0.0% |


## Critical Findings



## High Severity Findings



## Detailed Results by Service

### RDS.1 Service

| Check | Status | Severity | Resource | Region |
|-------|--------|----------|----------|--------|
| RDS Instance Encryption | OK | high | database-2 | N/A |
| RDS Instance Encryption | OK | high | docdb-test | N/A |
| RDS Instance Encryption | OK | high | oracletest | N/A |
| RDS Instance Encryption | OK | high | N/A | N/A |


### RDS.2 Service

| Check | Status | Severity | Resource | Region |
|-------|--------|----------|----------|--------|
| RDS Instance Public Access | OK | critical | database-2 | N/A |
| RDS Instance Public Access | OK | critical | docdb-test | N/A |
| RDS Instance Public Access | OK | critical | oracletest | N/A |
| RDS Instance Public Access | OK | critical | N/A | N/A |


### RDS.3 Service

| Check | Status | Severity | Resource | Region |
|-------|--------|----------|----------|--------|
| RDS Instance Backups | NEED_REVIEW | medium | database-2 | N/A |
| RDS Instance Backups | NEED_REVIEW | medium | docdb-test | N/A |
| RDS Instance Backups | OK | medium | oracletest | N/A |
| RDS Instance Backups | NEED_REVIEW | medium | N/A | N/A |


### VPC.1 Service

| Check | Status | Severity | Resource | Region |
|-------|--------|----------|----------|--------|
| VPC Flow Logs | ERROR | medium | vpc-0506bfa3604b99737 | N/A |
| VPC Flow Logs | ERROR | medium | vpc-010977eb5ea0c83b4 | N/A |


### VPC.2 Service

| Check | Status | Severity | Resource | Region |
|-------|--------|----------|----------|--------|
| Default VPC Usage | OK | low | vpc-0506bfa3604b99737 | N/A |
| Default VPC Usage | ERROR | low | vpc-010977eb5ea0c83b4 | N/A |


### EC2.1 Service

| Check | Status | Severity | Resource | Region |
|-------|--------|----------|----------|--------|
| Instance Metadata Service v2 | OK | medium | i-0895a496edd345e60 | N/A |
| Instance Metadata Service v2 | OK | medium | i-07367cf5081e8cb03 | N/A |
| Instance Metadata Service v2 | OK | medium | i-049a1aa87cb90698b | N/A |
| Instance Metadata Service v2 | OK | medium | i-08439a9f85c792044 | N/A |
| Instance Metadata Service v2 | OK | medium | i-089b73733dacb075c | N/A |
| Instance Metadata Service v2 | OK | medium | i-05daeef34271682f6 | N/A |
| Instance Metadata Service v2 | OK | medium | i-0624349388aa63df3 | N/A |
| Instance Metadata Service v2 | OK | medium | i-0a7e53709539e81f5 | N/A |
| Instance Metadata Service v2 | OK | medium | i-08a03ddf2bbae43ad | N/A |
| Instance Metadata Service v2 | OK | medium | i-0f856547d22f770a4 | N/A |
| Instance Metadata Service v2 | OK | medium | i-044db8570e7b1590b | N/A |
| Instance Metadata Service v2 | OK | medium | i-0a58034cf0bf4a069 | N/A |
| Instance Metadata Service v2 | OK | medium | i-0dc831eaf4bc99686 | N/A |
| Instance Metadata Service v2 | OK | medium | i-0f95195f4469942de | N/A |
| Instance Metadata Service v2 | OK | medium | i-0c92ec7eec5922bdd | N/A |
| Instance Metadata Service v2 | OK | medium | i-033d093e83b198e8f | N/A |
| Instance Metadata Service v2 | OK | medium | i-0f987f24a87603c07 | N/A |


### EC2.4 Service

| Check | Status | Severity | Resource | Region |
|-------|--------|----------|----------|--------|
| EBS Volume Encryption | ERROR | high | i-0895a496edd345e60 | N/A |
| EBS Volume Encryption | ERROR | high | i-07367cf5081e8cb03 | N/A |
| EBS Volume Encryption | ERROR | high | i-049a1aa87cb90698b | N/A |
| EBS Volume Encryption | ERROR | high | i-08439a9f85c792044 | N/A |
| EBS Volume Encryption | ERROR | high | i-089b73733dacb075c | N/A |
| EBS Volume Encryption | ERROR | high | i-05daeef34271682f6 | N/A |
| EBS Volume Encryption | ERROR | high | i-0624349388aa63df3 | N/A |
| EBS Volume Encryption | ERROR | high | i-0a7e53709539e81f5 | N/A |
| EBS Volume Encryption | ERROR | high | i-08a03ddf2bbae43ad | N/A |
| EBS Volume Encryption | ERROR | high | i-0f856547d22f770a4 | N/A |
| EBS Volume Encryption | ERROR | high | i-044db8570e7b1590b | N/A |
| EBS Volume Encryption | ERROR | high | i-0a58034cf0bf4a069 | N/A |
| EBS Volume Encryption | ERROR | high | i-0dc831eaf4bc99686 | N/A |
| EBS Volume Encryption | ERROR | high | i-0f95195f4469942de | N/A |
| EBS Volume Encryption | ERROR | high | i-0c92ec7eec5922bdd | N/A |
| EBS Volume Encryption | ERROR | high | i-033d093e83b198e8f | N/A |
| EBS Volume Encryption | ERROR | high | i-0f987f24a87603c07 | N/A |


### KMS.1 Service

| Check | Status | Severity | Resource | Region |
|-------|--------|----------|----------|--------|
| KMS Key Rotation | NEED_REVIEW | medium | 04d61437-7df6-4060-8f4b-f279c73cb099 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 171c027e-17d0-42c5-8c5f-91b2f9d9bfc2 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 1f4c5dbf-a178-4b26-915d-a4f48bec2c9c | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 2512dde2-7011-4f24-994f-5c91d8f76254 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 25f88473-a3bb-4d4a-a6ea-9bd24ccdda9b | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 32780a64-4e1e-4088-81fe-97a6fa01d7bb | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 36147aee-1225-45ef-bb6d-bd6d4d1344a7 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 42c09d59-6522-4d35-aa17-a7bdeebaa43b | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 4b0a33d1-6b8f-44cd-94c5-95a20d476f09 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 620686fe-8132-49a9-940e-11708eec1132 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 6569bcb6-3083-4a97-a3bc-0e713a681ae2 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 6595190e-67c3-4fab-b2a2-8595b0e4ee88 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 67e76862-7801-41e9-9d38-515510ee2d68 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 680f99b2-75cd-42f6-881d-3fdec343b9c6 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 68cc299d-bf3a-4f1c-97b2-fbd1e581e65a | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 6a915540-cbd3-42e5-88fc-84ba17ae5090 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 71b851c3-3d3e-4227-ba36-dec8450157d8 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 726b7c6e-c9e7-4fe5-8d3d-8774384df5e3 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 7699d831-c67a-471d-a99a-cf9a45baf38f | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 7f057f9a-7448-42b5-acd8-7735c4efd396 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 871a9d43-32ca-4688-843e-cbdd5dc50412 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 88d6ea89-bd9f-4e4d-bb0e-33d10f83a93f | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 89885bef-fae2-4db2-baee-7051c6d7e999 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | 94b8ad4f-766a-4f69-82ff-132692137fe0 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | a3a642c5-be1f-4977-b687-32741abf4348 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | ae7b19ec-0875-4ec4-97a8-ca5da558463a | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | b41395b4-a392-44eb-9036-db2264bc0f34 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | c04020e8-478e-4cf8-be25-38d14d4f5f1b | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | c76a956d-1dec-4afa-afb8-2dbab1c2f6ca | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | cbc9bfe6-ecb9-46bd-8a0f-a73ed15d4407 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | d8d9d27e-81db-4409-aca1-666aa9de4714 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | dda50ff8-30e2-4b3d-8e06-c8a06418d326 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | e40cd433-2e8a-4435-973e-edf9c1062af2 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | e6c94df8-19c2-4392-9ae5-56d3501e0bce | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | edaab79c-ae5a-4283-8ee4-866ad23f7046 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | efc7ce77-ff4d-471f-bffc-ed582b70ac84 | N/A |
| KMS Key Rotation | NEED_REVIEW | medium | mrk-255ef74b24174d6f97c0f37bbfd8e515 | N/A |


### KMS.2 Service

| Check | Status | Severity | Resource | Region |
|-------|--------|----------|----------|--------|
| KMS Key Policy | ERROR | high | 04d61437-7df6-4060-8f4b-f279c73cb099 | N/A |
| KMS Key Policy | ERROR | high | 171c027e-17d0-42c5-8c5f-91b2f9d9bfc2 | N/A |
| KMS Key Policy | ERROR | high | 1f4c5dbf-a178-4b26-915d-a4f48bec2c9c | N/A |
| KMS Key Policy | ERROR | high | 2512dde2-7011-4f24-994f-5c91d8f76254 | N/A |
| KMS Key Policy | ERROR | high | 25f88473-a3bb-4d4a-a6ea-9bd24ccdda9b | N/A |
| KMS Key Policy | ERROR | high | 32780a64-4e1e-4088-81fe-97a6fa01d7bb | N/A |
| KMS Key Policy | ERROR | high | 36147aee-1225-45ef-bb6d-bd6d4d1344a7 | N/A |
| KMS Key Policy | ERROR | high | 42c09d59-6522-4d35-aa17-a7bdeebaa43b | N/A |
| KMS Key Policy | ERROR | high | 4b0a33d1-6b8f-44cd-94c5-95a20d476f09 | N/A |
| KMS Key Policy | ERROR | high | 620686fe-8132-49a9-940e-11708eec1132 | N/A |
| KMS Key Policy | ERROR | high | 6569bcb6-3083-4a97-a3bc-0e713a681ae2 | N/A |
| KMS Key Policy | ERROR | high | 6595190e-67c3-4fab-b2a2-8595b0e4ee88 | N/A |
| KMS Key Policy | ERROR | high | 67e76862-7801-41e9-9d38-515510ee2d68 | N/A |
| KMS Key Policy | ERROR | high | 680f99b2-75cd-42f6-881d-3fdec343b9c6 | N/A |
| KMS Key Policy | ERROR | high | 68cc299d-bf3a-4f1c-97b2-fbd1e581e65a | N/A |
| KMS Key Policy | ERROR | high | 6a915540-cbd3-42e5-88fc-84ba17ae5090 | N/A |
| KMS Key Policy | ERROR | high | 71b851c3-3d3e-4227-ba36-dec8450157d8 | N/A |
| KMS Key Policy | ERROR | high | 726b7c6e-c9e7-4fe5-8d3d-8774384df5e3 | N/A |
| KMS Key Policy | ERROR | high | 7699d831-c67a-471d-a99a-cf9a45baf38f | N/A |
| KMS Key Policy | ERROR | high | 7f057f9a-7448-42b5-acd8-7735c4efd396 | N/A |
| KMS Key Policy | ERROR | high | 871a9d43-32ca-4688-843e-cbdd5dc50412 | N/A |
| KMS Key Policy | ERROR | high | 88d6ea89-bd9f-4e4d-bb0e-33d10f83a93f | N/A |
| KMS Key Policy | ERROR | high | 89885bef-fae2-4db2-baee-7051c6d7e999 | N/A |
| KMS Key Policy | ERROR | high | 94b8ad4f-766a-4f69-82ff-132692137fe0 | N/A |
| KMS Key Policy | ERROR | high | a3a642c5-be1f-4977-b687-32741abf4348 | N/A |
| KMS Key Policy | ERROR | high | ae7b19ec-0875-4ec4-97a8-ca5da558463a | N/A |
| KMS Key Policy | ERROR | high | b41395b4-a392-44eb-9036-db2264bc0f34 | N/A |
| KMS Key Policy | ERROR | high | c04020e8-478e-4cf8-be25-38d14d4f5f1b | N/A |
| KMS Key Policy | ERROR | high | c76a956d-1dec-4afa-afb8-2dbab1c2f6ca | N/A |
| KMS Key Policy | ERROR | high | cbc9bfe6-ecb9-46bd-8a0f-a73ed15d4407 | N/A |
| KMS Key Policy | ERROR | high | d8d9d27e-81db-4409-aca1-666aa9de4714 | N/A |
| KMS Key Policy | ERROR | high | dda50ff8-30e2-4b3d-8e06-c8a06418d326 | N/A |
| KMS Key Policy | ERROR | high | e40cd433-2e8a-4435-973e-edf9c1062af2 | N/A |
| KMS Key Policy | ERROR | high | e6c94df8-19c2-4392-9ae5-56d3501e0bce | N/A |
| KMS Key Policy | ERROR | high | edaab79c-ae5a-4283-8ee4-866ad23f7046 | N/A |
| KMS Key Policy | ERROR | high | efc7ce77-ff4d-471f-bffc-ed582b70ac84 | N/A |
| KMS Key Policy | ERROR | high | mrk-255ef74b24174d6f97c0f37bbfd8e515 | N/A |




## Recommendations

1. **Immediate Action Required**: Address all critical severity findings
2. **High Priority**: Resolve high severity findings within 30 days
3. **Medium Priority**: Plan remediation for medium severity findings
4. **Monitoring**: Implement continuous monitoring for identified issues
5. **Review**: Regularly review and update security configurations

## Compliance Status

Based on the CIS AWS Foundations Benchmark profile:
- **Center for Internet Security AWS Foundations Benchmark v1.4.0**
- **Overall Compliance**: 21.77%

---

*This report was generated by AWS Security Audit Tool v1.0.0 on 2025-07-09T10:21:02.930362Z*
