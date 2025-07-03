# AWS Security Audit Tool - System Architecture

## High-Level Architecture Overview

```mermaid
graph TB
    subgraph "User Interface Layer"
        CLI[Command Line Interface]
        Config[Configuration Files]
    end
    
    subgraph "Application Layer"
        InputVal[Input Validator]
        AuthMgr[Authentication Manager]
        ProfileMgr[Profile Manager]
        Orchestrator[Audit Orchestrator]
    end
    
    subgraph "Security Checks Layer"
        S3Check[S3 Security Checks]
        EC2Check[EC2 Security Checks]
        EKSCheck[EKS Security Checks]
        ElastiCacheCheck[ElastiCache Security Checks]
        RDSCheck[RDS Security Checks]
        DynamoDBCheck[DynamoDB Security Checks]
        VPCCheck[VPC Security Checks]
        SGCheck[Security Groups Checks]
        KMSCheck[KMS Security Checks]
        LBCheck[Load Balancer Security Checks]
    end
    
    subgraph "AWS Integration Layer"
        AWSClient[AWS Client Manager]
        APIGateway[AWS API Gateway]
        RateLimit[Rate Limiter]
        ErrorHandler[Error Handler]
    end
    
    subgraph "Processing Layer"
        ResultProc[Result Processor]
        Classifier[Status Classifier]
        Scorer[Score Calculator]
        Aggregator[Result Aggregator]
    end
    
    subgraph "Output Layer"
        ReportGen[Report Generator]
        MDExport[Markdown Exporter]
        JSONExport[JSON Exporter]
        CSVExport[CSV Exporter]
    end
    
    subgraph "External Systems"
        AWS[AWS Services]
        FileSystem[File System]
        Logs[Log Files]
    end
    
    CLI --> InputVal
    Config --> ProfileMgr
    InputVal --> AuthMgr
    AuthMgr --> AWSClient
    ProfileMgr --> Orchestrator
    Orchestrator --> IAMCheck
    Orchestrator --> S3Check
    Orchestrator --> EC2Check
    Orchestrator --> EKSCheck
    Orchestrator --> ElastiCacheCheck
    Orchestrator --> RDSCheck
    Orchestrator --> DynamoDBCheck
    Orchestrator --> VPCCheck
    Orchestrator --> SGCheck
    Orchestrator --> KMSCheck
    Orchestrator --> LBCheck
    
    IAMCheck --> AWSClient
    S3Check --> AWSClient
    EC2Check --> AWSClient
    EKSCheck --> AWSClient
    ElastiCacheCheck --> AWSClient
    RDSCheck --> AWSClient
    DynamoDBCheck --> AWSClient
    VPCCheck --> AWSClient
    SGCheck --> AWSClient
    KMSCheck --> AWSClient
    LBCheck --> AWSClient
    
    AWSClient --> APIGateway
    AWSClient --> RateLimit
    AWSClient --> ErrorHandler
    APIGateway --> AWS
    
    IAMCheck --> ResultProc
    S3Check --> ResultProc
    EC2Check --> ResultProc
    EKSCheck --> ResultProc
    ElastiCacheCheck --> ResultProc
    RDSCheck --> ResultProc
    DynamoDBCheck --> ResultProc
    VPCCheck --> ResultProc
    SGCheck --> ResultProc
    KMSCheck --> ResultProc
    LBCheck --> ResultProc
    
    ResultProc --> Classifier
    Classifier --> Scorer
    Scorer --> Aggregator
    Aggregator --> ReportGen
    
    ReportGen --> MDExport
    ReportGen --> JSONExport
    ReportGen --> CSVExport
    
    MDExport --> FileSystem
    JSONExport --> FileSystem
    CSVExport --> FileSystem
    ErrorHandler --> Logs
    
    style CLI fill:#e1f5fe
    style AWS fill:#fff3e0
    style FileSystem fill:#e8f5e8
```

## Component Architecture Details

### 1. Command Line Interface (CLI)

```mermaid
classDiagram
    class CLI {
        +String account_id
        +String auth_method
        +String security_profile
        +String[] output_formats
        +String output_dir
        +Boolean verbose
        +parse_arguments()
        +validate_arguments()
        +display_help()
        +display_version()
    }
    
    class ArgumentParser {
        +add_argument()
        +parse_args()
        +error()
    }
    
    class ConfigLoader {
        +load_config_file()
        +merge_cli_config()
        +validate_config()
    }
    
    CLI --> ArgumentParser
    CLI --> ConfigLoader
```

### 2. Input Validation Layer

```mermaid
classDiagram
    class InputValidator {
        +validate_account_id(String)
        +validate_auth_method(String)
        +validate_security_profile(String)
        +validate_output_formats(String[])
        +validate_output_directory(String)
        +ValidationResult validate_all()
    }
    
    class ValidationResult {
        +Boolean is_valid
        +String[] errors
        +String[] warnings
        +Dictionary validated_data
    }
    
    class AccountIdValidator {
        +REGEX_PATTERN
        +validate(String)
    }
    
    class AuthMethodValidator {
        +VALID_METHODS[]
        +validate(String)
        +test_credentials()
    }
    
    InputValidator --> ValidationResult
    InputValidator --> AccountIdValidator
    InputValidator --> AuthMethodValidator
```

### 3. Authentication Manager

```mermaid
classDiagram
    class AuthenticationManager {
        +String auth_method
        +Dictionary credentials
        +Session aws_session
        +authenticate()
        +test_connectivity()
        +refresh_credentials()
        +get_session()
    }
    
    class ProfileAuth {
        +String profile_name
        +authenticate()
    }
    
    class RoleAuth {
        +String role_arn
        +String session_name
        +authenticate()
    }
    
    class KeyAuth {
        +String access_key
        +String secret_key
        +authenticate()
    }
    
    class InstanceAuth {
        +authenticate()
    }
    
    AuthenticationManager --> ProfileAuth
    AuthenticationManager --> RoleAuth
    AuthenticationManager --> KeyAuth
    AuthenticationManager --> InstanceAuth
```

### 4. AWS Client Manager

```mermaid
classDiagram
    class AWSClientManager {
        +Session session
        +Dictionary clients
        +RateLimiter rate_limiter
        +ErrorHandler error_handler
        +get_client(String service)
        +make_request(String service, String method, Dictionary params)
        +handle_pagination(Iterator)
        +retry_with_backoff(Function)
    }
    
    class RateLimiter {
        +Dictionary limits
        +Dictionary current_usage
        +wait_if_needed(String service)
        +update_usage(String service)
    }
    
    class ErrorHandler {
        +handle_client_error(Exception)
        +handle_throttling(Exception)
        +handle_permissions(Exception)
        +should_retry(Exception)
    }
    
    AWSClientManager --> RateLimiter
    AWSClientManager --> ErrorHandler
```

### 5. Security Checks Engine

```mermaid
classDiagram
    class SecurityChecksEngine {
        +Dictionary check_categories
        +ThreadPoolExecutor executor
        +execute_all_checks()
        +execute_category_checks(String category)
        +collect_results()
    }
    
    class BaseSecurityCheck {
        +String check_id
        +String name
        +String description
        +String severity
        +execute()
        +collect_evidence()
        +get_remediation()
    }
    
    
    class S3SecurityChecks {
        +check_public_access()
        +check_encryption()
        +check_logging()
        +check_versioning()
        +check_lifecycle_policy()
    }
    
    class EC2SecurityChecks {
        +check_ami_security()
        +check_key_pairs()
        +check_monitoring()
        +check_patch_management()
        +check_ebs_encryption()
        +check_instance_metadata()
        +check_termination_protection()
    }
    
    class EKSSecurityChecks {
        +check_cluster_endpoint_access()
        +check_cluster_logging()
        +check_node_group_security()
        +check_pod_security_standards()
        +check_network_policies()
        +check_rbac_configuration()
        +check_secrets_management()
    }
    
    class ElastiCacheSecurityChecks {
        +check_encryption_in_transit()
        +check_encryption_at_rest()
        +check_subnet_groups()
        +check_parameter_groups()
        +check_backup_configuration()
        +check_auth_token()
    }
    
    class RDSSecurityChecks {
        +check_encryption_at_rest()
        +check_encryption_in_transit()
        +check_publicly_accessible()
        +check_automated_backups()
        +check_multi_az_deployment()
        +check_parameter_groups()
        +check_monitoring()
        +check_deletion_protection()
    }
    
    class DynamoDBSecurityChecks {
        +check_encryption_at_rest()
        +check_point_in_time_recovery()
        +check_vpc_endpoints()
        +check_access_control()
        +check_contributor_insights()
        +check_global_tables()
        +check_auto_scaling()
    }
    
    class SecurityGroupsChecks {
        +check_inbound_rules()
        +check_outbound_rules()
        +check_unused_security_groups()
        +check_rule_overlap()
        +check_port_management()
        +check_ssh_rdp_access()
        +check_default_security_groups()
    }
    
    class LoadBalancerSecurityChecks {
        +check_ssl_tls_configuration()
        +check_access_logs()
        +check_security_groups()
        +check_cross_zone_load_balancing()
        +check_health_checks()
        +check_deletion_protection()
        +check_waf_integration()
        +check_listener_security()
    }
    
    SecurityChecksEngine --> BaseSecurityCheck
    BaseSecurityCheck <|-- IAMSecurityChecks
    BaseSecurityCheck <|-- S3SecurityChecks
    BaseSecurityCheck <|-- EC2SecurityChecks
    BaseSecurityCheck <|-- EKSSecurityChecks
    BaseSecurityCheck <|-- ElastiCacheSecurityChecks
    BaseSecurityCheck <|-- RDSSecurityChecks
    BaseSecurityCheck <|-- DynamoDBSecurityChecks
    BaseSecurityCheck <|-- SecurityGroupsChecks
    BaseSecurityCheck <|-- LoadBalancerSecurityChecks
```

### 6. Result Processing Layer

```mermaid
classDiagram
    class ResultProcessor {
        +List raw_results
        +process_results()
        +classify_results()
        +calculate_scores()
        +aggregate_results()
    }
    
    class StatusClassifier {
        +classify_result(CheckResult)
        +apply_risk_scoring()
        +determine_status()
    }
    
    class ScoreCalculator {
        +calculate_category_score(List results)
        +calculate_overall_score(Dictionary categories)
        +determine_risk_level(Float score)
    }
    
    class CheckResult {
        +String check_id
        +String name
        +String status
        +String severity
        +String description
        +String evidence
        +String remediation
        +Float score
    }
    
    ResultProcessor --> StatusClassifier
    ResultProcessor --> ScoreCalculator
    ResultProcessor --> CheckResult
```

### 7. Report Generation Layer

```mermaid
classDiagram
    class ReportGenerator {
        +Dictionary results
        +String template_dir
        +generate_all_reports()
        +generate_markdown_report()
        +generate_json_export()
        +generate_csv_export()
    }
    
    class MarkdownReporter {
        +generate_executive_summary()
        +generate_detailed_findings()
        +format_tables()
        +apply_styling()
    }
    
    class JSONExporter {
        +structure_data()
        +serialize_results()
        +validate_json()
    }
    
    class CSVExporter {
        +flatten_results()
        +create_csv_rows()
        +write_csv_file()
    }
    
    class ReportTemplate {
        +String template_content
        +render(Dictionary data)
    }
    
    ReportGenerator --> MarkdownReporter
    ReportGenerator --> JSONExporter
    ReportGenerator --> CSVExporter
    ReportGenerator --> ReportTemplate
```

## Data Flow Architecture

```mermaid
flowchart LR
    subgraph "Input Data"
        A1[Account ID]
        A2[Auth Method]
        A3[Security Profile]
        A4[CLI Options]
    end
    
    subgraph "Configuration"
        B1[Security Profiles]
        B2[Check Definitions]
        B3[Thresholds]
        B4[Templates]
    end
    
    subgraph "AWS Data"
        C1[IAM Resources]
        C2[S3 Buckets]
        C3[EC2 Instances]
        C4[VPC Resources]
        C5[CloudTrail Logs]
        C6[KMS Keys]
    end
    
    subgraph "Processing"
        D1[Validation]
        D2[Authentication]
        D3[Discovery]
        D4[Security Checks]
        D5[Classification]
        D6[Scoring]
    end
    
    subgraph "Output Data"
        E1[Markdown Report]
        E2[JSON Export]
        E3[CSV Export]
        E4[Log Files]
    end
    
    A1 --> D1
    A2 --> D1
    A3 --> D1
    A4 --> D1
    
    B1 --> D4
    B2 --> D4
    B3 --> D5
    B4 --> E1
    
    D1 --> D2
    D2 --> D3
    D3 --> C1
    D3 --> C2
    D3 --> C3
    D3 --> C4
    D3 --> C5
    D3 --> C6
    
    C1 --> D4
    C2 --> D4
    C3 --> D4
    C4 --> D4
    C5 --> D4
    C6 --> D4
    
    D4 --> D5
    D5 --> D6
    D6 --> E1
    D6 --> E2
    D6 --> E3
    D4 --> E4
    
    style A1 fill:#e3f2fd
    style E1 fill:#c8e6c9
    style E2 fill:#c8e6c9
    style E3 fill:#c8e6c9
```

## Security Check Module Architecture

```mermaid
graph TB
    subgraph "Security Check Framework"
        BaseCheck[Base Security Check]
        CheckRegistry[Check Registry]
        CheckExecutor[Check Executor]
    end
    
    subgraph "IAM Checks"
        IAM1[Root MFA Check]
        IAM2[User MFA Check]
        IAM3[Password Policy Check]
        IAM4[Access Key Age Check]
        IAM5[Privilege Escalation Check]
    end
    
    subgraph "S3 Checks"
        S3_1[Public Access Check]
        S3_2[Encryption Check]
        S3_3[Logging Check]
        S3_4[Versioning Check]
        S3_5[Lifecycle Check]
    end
    
    subgraph "EC2 Checks"
        EC2_1[Security Groups Check]
        EC2_2[Key Pairs Check]
        EC2_3[AMI Security Check]
        EC2_4[Monitoring Check]
        EC2_5[Patch Management Check]
    end
    
    subgraph "VPC Checks"
        VPC1[Network ACL Check]
        VPC2[Flow Logs Check]
        VPC3[Peering Check]
        VPC4[NAT Gateway Check]
        VPC5[Route Tables Check]
    end
    
    subgraph "CloudTrail Checks"
        CT1[Trail Configuration Check]
        CT2[Log Integrity Check]
        CT3[CloudWatch Integration Check]
        CT4[S3 Bucket Security Check]
    end
    
    subgraph "KMS Checks"
        KMS1[Key Rotation Check]
        KMS2[Key Policies Check]
        KMS3[Key Usage Check]
        KMS4[Cross-Account Access Check]
    end
    
    BaseCheck --> IAM1
    BaseCheck --> IAM2
    BaseCheck --> IAM3
    BaseCheck --> IAM4
    BaseCheck --> IAM5
    
    BaseCheck --> S3_1
    BaseCheck --> S3_2
    BaseCheck --> S3_3
    BaseCheck --> S3_4
    BaseCheck --> S3_5
    
    BaseCheck --> EC2_1
    BaseCheck --> EC2_2
    BaseCheck --> EC2_3
    BaseCheck --> EC2_4
    BaseCheck --> EC2_5
    
    BaseCheck --> VPC1
    BaseCheck --> VPC2
    BaseCheck --> VPC3
    BaseCheck --> VPC4
    BaseCheck --> VPC5
    
    BaseCheck --> CT1
    BaseCheck --> CT2
    BaseCheck --> CT3
    BaseCheck --> CT4
    
    BaseCheck --> KMS1
    BaseCheck --> KMS2
    BaseCheck --> KMS3
    BaseCheck --> KMS4
    
    CheckRegistry --> CheckExecutor
    CheckExecutor --> BaseCheck
```

## Threading and Concurrency Model

```mermaid
graph TB
    subgraph "Main Thread"
        MainProc[Main Process]
        Coordinator[Execution Coordinator]
        ResultCollector[Result Collector]
    end
    
    subgraph "Worker Thread Pool"
        T1[Worker Thread 1]
        T2[Worker Thread 2]
        T3[Worker Thread 3]
        T4[Worker Thread 4]
        T5[Worker Thread 5]
        T6[Worker Thread 6]
    end
    
    subgraph "Task Queue"
        Q1[IAM Tasks Queue]
        Q2[S3 Tasks Queue]
        Q3[EC2 Tasks Queue]
        Q4[VPC Tasks Queue]
        Q5[CloudTrail Tasks Queue]
        Q6[KMS Tasks Queue]
    end
    
    subgraph "Shared Resources"
        AWSClients[AWS Client Pool]
        ResultStore[Thread-Safe Result Store]
        ErrorLogger[Thread-Safe Error Logger]
    end
    
    MainProc --> Coordinator
    Coordinator --> Q1
    Coordinator --> Q2
    Coordinator --> Q3
    Coordinator --> Q4
    Coordinator --> Q5
    Coordinator --> Q6
    
    Q1 --> T1
    Q2 --> T2
    Q3 --> T3
    Q4 --> T4
    Q5 --> T5
    Q6 --> T6
    
    T1 --> AWSClients
    T2 --> AWSClients
    T3 --> AWSClients
    T4 --> AWSClients
    T5 --> AWSClients
    T6 --> AWSClients
    
    T1 --> ResultStore
    T2 --> ResultStore
    T3 --> ResultStore
    T4 --> ResultStore
    T5 --> ResultStore
    T6 --> ResultStore
    
    T1 --> ErrorLogger
    T2 --> ErrorLogger
    T3 --> ErrorLogger
    T4 --> ErrorLogger
    T5 --> ErrorLogger
    T6 --> ErrorLogger
    
    ResultStore --> ResultCollector
    ResultCollector --> MainProc
```

## File System Organization

```
aws-security-audit/
├── src/
│   ├── __init__.py
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   └── argument_parser.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── orchestrator.py
│   │   ├── input_validator.py
│   │   └── config_manager.py
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── auth_manager.py
│   │   └── aws_client.py
│   ├── checks/
│   │   ├── __init__.py
│   │   ├── base_check.py
│   │   ├── s3_checks.py
│   │   ├── ec2_checks.py
│   │   ├── eks_checks.py
│   │   ├── elasticache_checks.py
│   │   ├── rds_checks.py
│   │   ├── dynamodb_checks.py
│   │   ├── vpc_checks.py
│   │   ├── security_groups_checks.py
│   │   ├── kms_checks.py
│   │   └── load_balancer_checks.py
│   ├── processing/
│   │   ├── __init__.py
│   │   ├── result_processor.py
│   │   ├── classifier.py
│   │   └── scorer.py
│   ├── reporting/
│   │   ├── __init__.py
│   │   ├── report_generator.py
│   │   ├── markdown_reporter.py
│   │   ├── json_exporter.py
│   │   └── csv_exporter.py
│   └── utils/
│       ├── __init__.py
│       ├── logger.py
│       ├── exceptions.py
│       └── helpers.py
├── config/
│   ├── security_profiles/
│   │   ├── cis_aws_foundations.yaml
│   │   ├── nist_cybersecurity.yaml
│   │   └── custom_profile.yaml
│   └── templates/
│       ├── report_template.md
│       └── summary_template.md
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── docs/
│   ├── aws-security-audit-plan.md
│   ├── aws-security-audit-workflow.md
│   ├── aws-security-audit-flowchart.md
│   └── aws-security-audit-architecture.md
├── requirements.txt
├── setup.py
└── README.md
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Local Development"
        DevEnv[Development Environment]
        LocalAWS[Local AWS CLI]
        TestAccount[Test AWS Account]
    end
    
    subgraph "CI/CD Pipeline"
        GitRepo[Git Repository]
        BuildServer[Build Server]
        TestSuite[Test Suite]
        Artifacts[Build Artifacts]
    end
    
    subgraph "Distribution"
        PyPI[PyPI Package]
        DockerHub[Docker Image]
        GitReleases[GitHub Releases]
    end
    
    subgraph "Production Usage"
        UserWorkstation[User Workstation]
        CloudShell[AWS CloudShell]
        EC2Instance[EC2 Instance]
        CIPipeline[CI/CD Pipeline]
    end
    
    DevEnv --> GitRepo
    LocalAWS --> TestAccount
    GitRepo --> BuildServer
    BuildServer --> TestSuite
    TestSuite --> Artifacts
    Artifacts --> PyPI
    Artifacts --> DockerHub
    Artifacts --> GitReleases
    
    PyPI --> UserWorkstation
    DockerHub --> CloudShell
    GitReleases --> EC2Instance
    PyPI --> CIPipeline
    
    UserWorkstation --> TestAccount
    CloudShell --> TestAccount
    EC2Instance --> TestAccount
    CIPipeline --> TestAccount
```

## Security Considerations in Architecture

```mermaid
graph TB
    subgraph "Security Layers"
        InputSan[Input Sanitization]
        AuthSec[Authentication Security]
        CredMgmt[Credential Management]
        DataProt[Data Protection]
        AuditLog[Audit Logging]
    end
    
    subgraph "Threat Mitigation"
        InjectionPrev[Injection Prevention]
        PrivEsc[Privilege Escalation Prevention]
        DataLeak[Data Leakage Prevention]
        DDOS[DoS Protection]
        CredTheft[Credential Theft Prevention]
    end
    
    subgraph "Compliance"
        MinPriv[Minimum Privilege]
        DataRetent[Data Retention]
        Encrypt[Encryption at Rest/Transit]
        AccessCtrl[Access Control]
    end
    
    InputSan --> InjectionPrev
    AuthSec --> PrivEsc
    CredMgmt --> CredTheft
    DataProt --> DataLeak
    AuditLog --> AccessCtrl
    
    InjectionPrev --> MinPriv
    PrivEsc --> MinPriv
    DataLeak --> Encrypt
    DDOS --> AccessCtrl
    CredTheft --> DataRetent
    
    style InputSan fill:#ffcdd2
    style AuthSec fill:#ffcdd2
    style CredMgmt fill:#ffcdd2
    style DataProt fill:#ffcdd2
    style AuditLog fill:#ffcdd2
```