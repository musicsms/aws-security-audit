# AWS Security Audit Tool - Detailed Flowchart

## Complete Process Flowchart

```mermaid
flowchart TD
    A[AWS Security Audit Tool Start] --> B[Parse Command Line Arguments]
    B --> C[Load Configuration File]
    C --> D[Validate AWS Account ID Format]
    D --> E{Account ID Valid?}
    E -->|No| F[Display Account ID Error]
    E -->|Yes| G[Validate Authentication Method]
    G --> H{Auth Method Valid?}
    H -->|No| I[Display Auth Method Error]
    H -->|Yes| J[Load Security Profile]
    J --> K{Profile Found?}
    K -->|No| L[Display Profile Error]
    K -->|Yes| M[Initialize AWS Session]
    
    F --> END1[Exit Code 1]
    I --> END1
    L --> END1
    
    M --> N[Test AWS Connectivity]
    N --> O{Connection Success?}
    O -->|No| P[Display Connection Error]
    O -->|Yes| Q[Verify AWS Permissions]
    P --> END2[Exit Code 2]
    
    Q --> R{Permissions OK?}
    R -->|No| S[Display Permission Error]
    R -->|Yes| T[Start Resource Discovery]
    S --> END3[Exit Code 3]
    
    T --> U[Discover IAM Resources]
    T --> V[Discover S3 Resources]
    T --> W[Discover EC2 Resources]
    T --> X[Discover VPC Resources]
    T --> Y[Discover CloudTrail Resources]
    T --> Z[Discover KMS Resources]
    
    U --> AA[Execute IAM Security Checks]
    V --> BB[Execute S3 Security Checks]
    W --> CC[Execute EC2 Security Checks]
    X --> DD[Execute VPC Security Checks]
    Y --> EE[Execute CloudTrail Security Checks]
    Z --> FF[Execute KMS Security Checks]
    
    AA --> GG[Process IAM Results]
    BB --> HH[Process S3 Results]
    CC --> II[Process EC2 Results]
    DD --> JJ[Process VPC Results]
    EE --> KK[Process CloudTrail Results]
    FF --> LL[Process KMS Results]
    
    GG --> MM[Aggregate All Results]
    HH --> MM
    II --> MM
    JJ --> MM
    KK --> MM
    LL --> MM
    
    YY --> ZZ[Calculate Overall Score]
    NN --> OO[Generate Executive Summary]
    OO --> PP[Create Detailed Report]
    PP --> QQ[Format Markdown Output]
    QQ --> RR{Export JSON?}
    RR -->|Yes| SS[Generate JSON Export]
    RR -->|No| TT{Export CSV?}
    SS --> TT
    TT -->|Yes| UU[Generate CSV Export]
    TT -->|No| VV[Save Reports to Disk]
    UU --> VV
    VV --> WW[Display Completion Summary]
    WW --> XX[End Successfully]
    
    style A fill:#e1f5fe
    style JJJ fill:#c8e6c9
    style END1 fill:#ffcdd2
    style END2 fill:#ffcdd2
    style END3 fill:#ffcdd2
```

## S3 Security Checks Detailed Flow

```mermaid
flowchart TD
    A[Start S3 Checks] --> B[List All S3 Buckets]
    B --> C{MFA Enabled?}
    C -->|Yes| D[Mark OK]
    C -->|No| E[Mark NOK]
    C -->|Hardware Token| F[Mark NEED_REVIEW]
    
    D --> G[Check User MFA Enforcement]
    E --> G
    F --> G
    
    G --> H[Get All IAM Users]
    H --> I[Count Users with MFA]
    I --> J{Coverage >= 95%?}
    J -->|Yes| K[Mark OK]
    J -->|No| L{Coverage >= 80%?}
    L -->|Yes| M[Mark NEED_REVIEW]
    L -->|No| N[Mark NOK]
    
    K --> O[Check Password Policy]
    M --> O
    N --> O
    
    O --> P[Get Account Password Policy]
    P --> Q{Strong Policy?}
    Q -->|Yes| R[Mark OK]
    Q -->|Partial| S[Mark NEED_REVIEW]
    Q -->|No| T[Mark NOK]
    
    R --> U[Check Access Key Age]
    S --> U
    T --> U
    
    U --> V[List All Access Keys]
    V --> W[Calculate Key Ages]
    W --> X{Any Keys > 90 Days?}
    X -->|No| Y[Mark OK]
    X -->|Yes| Z{Any Keys > 180 Days?}
    Z -->|No| AA[Mark NEED_REVIEW]
    Z -->|Yes| BB[Mark NOK]
    
    Y --> CC[Check Privilege Escalation]
    AA --> CC
    BB --> CC
    
    CC --> DD[Analyze Role Policies]
    DD --> EE{Admin Privileges?}
    EE -->|No| FF[Mark OK]
    EE -->|Limited| GG[Mark NEED_REVIEW]
    EE -->|Yes| HH[Mark NOK]
    
    FF --> II[Complete IAM Checks]
    GG --> II
    HH --> II
    
    style A fill:#e8f5e8
    style II fill:#c8e6c9
    style D fill:#c8e6c9
    style K fill:#c8e6c9
    style R fill:#c8e6c9
    style Y fill:#c8e6c9
    style FF fill:#c8e6c9
    style E fill:#ffcdd2
    style N fill:#ffcdd2
    style T fill:#ffcdd2
    style BB fill:#ffcdd2
    style HH fill:#ffcdd2
    style F fill:#fff3e0
    style M fill:#fff3e0
    style S fill:#fff3e0
    style AA fill:#fff3e0
    style GG fill:#fff3e0
```

## S3 Security Checks Detailed Flow

```mermaid
flowchart TD
    A[Start S3 Checks] --> B[List All S3 Buckets]
    B --> C[For Each Bucket]
    C --> D[Check Public Access Block]
    D --> E{Public Access Blocked?}
    E -->|Yes| F[Mark OK]
    E -->|Partial| G[Mark NEED_REVIEW]
    E -->|No| H[Mark NOK]
    
    F --> I[Check Bucket Encryption]
    G --> I
    H --> I
    
    I --> J[Get Bucket Encryption]
    J --> K{Encryption Enabled?}
    K -->|KMS| L[Mark OK]
    K -->|AES-256| M[Mark NEED_REVIEW]
    K -->|None| N[Mark NOK]
    
    L --> O[Check Access Logging]
    M --> O
    N --> O
    
    O --> P[Get Bucket Logging]
    P --> Q{Logging Enabled?}
    Q -->|Yes| R[Mark OK]
    Q -->|Partial| S[Mark NEED_REVIEW]
    Q -->|No| T[Mark NOK]
    
    R --> U[Check Versioning]
    S --> U
    T --> U
    
    U --> V[Get Bucket Versioning]
    V --> W{Versioning Status?}
    W -->|Enabled| X[Mark OK]
    W -->|Suspended| Y[Mark NEED_REVIEW]
    W -->|Disabled| Z[Mark NOK]
    
    X --> AA[Check Lifecycle Policy]
    Y --> AA
    Z --> AA
    
    AA --> BB[Get Lifecycle Configuration]
    BB --> CC{Lifecycle Rules?}
    CC -->|Comprehensive| DD[Mark OK]
    CC -->|Basic| EE[Mark NEED_REVIEW]
    CC -->|None| FF[Mark NOK]
    
    DD --> GG{More Buckets?}
    EE --> GG
    FF --> GG
    GG -->|Yes| C
    GG -->|No| HH[Complete S3 Checks]
    
    style A fill:#e8f5e8
    style HH fill:#c8e6c9
```

## Result Classification Decision Tree

```mermaid
flowchart TD
    A[Security Check Completed] --> B[Extract Check Result]
    B --> C{Check Type?}
    
    C -->|Binary| D{Passed?}
    C -->|Threshold| E[Calculate Score]
    C -->|Configuration| F[Analyze Config]
    
    D -->|Yes| G[Mark OK]
    D -->|No| H[Mark NOK]
    
    E --> I{Score >= 90%?}
    I -->|Yes| J[Mark OK]
    I -->|No| K{Score >= 70%?}
    K -->|Yes| L[Mark NEED_REVIEW]
    K -->|No| M[Mark NOK]
    
    F --> N{Best Practice?}
    N -->|Yes| O[Mark OK]
    N -->|Acceptable| P[Mark NEED_REVIEW]
    N -->|Poor| Q[Mark NOK]
    
    G --> R[Add Evidence]
    H --> S[Add Remediation]
    J --> R
    L --> T[Add Review Notes]
    M --> S
    O --> R
    P --> T
    Q --> S
    
    R --> U[Update Category Score]
    S --> U
    T --> U
    
    U --> V[Store Result]
    V --> W[Next Check]
    
    style G fill:#c8e6c9
    style J fill:#c8e6c9
    style O fill:#c8e6c9
    style H fill:#ffcdd2
    style M fill:#ffcdd2
    style Q fill:#ffcdd2
    style L fill:#fff3e0
    style P fill:#fff3e0
```

## Report Generation Process Flow

```mermaid
flowchart TD
    A[Start Report Generation] --> B[Aggregate Check Results]
    B --> C[Calculate Category Scores]
    C --> D[Calculate Overall Score]
    D --> E[Determine Risk Level]
    E --> F{Risk Level?}
    F -->|Low| G[Green Status]
    F -->|Medium| H[Yellow Status]
    F -->|High| I[Orange Status]
    F -->|Critical| J[Red Status]
    
    G --> K[Generate Executive Summary]
    H --> K
    I --> K
    J --> K
    
    K --> L[Create Summary Statistics]
    L --> M[List Top Findings]
    M --> N[Add Recommendations]
    N --> O[Format Executive Section]
    O --> P[Generate Detailed Findings]
    P --> Q[For Each Category]
    Q --> R[List Category Results]
    R --> S[Add Evidence Details]
    S --> T[Add Remediation Steps]
    T --> U{More Categories?}
    U -->|Yes| Q
    U -->|No| V[Format Detailed Section]
    V --> W[Combine Sections]
    W --> X[Apply Markdown Formatting]
    X --> Y[Save Primary Report]
    Y --> Z[Generate JSON Structure]
    Z --> AA[Export JSON File]
    AA --> BB[Generate CSV Data]
    BB --> CC[Export CSV File]
    CC --> DD[Create File Manifest]
    DD --> EE[Report Generation Complete]
    
    style A fill:#e8f5e8
    style EE fill:#c8e6c9
    style G fill:#c8e6c9
    style H fill:#fff3e0
    style I fill:#ffb74d
    style J fill:#ffcdd2
```

## Error Handling and Recovery Flow

```mermaid
flowchart TD
    A[Error Detected] --> B[Log Error Details]
    B --> C{Error Category?}
    
    C -->|Authentication| D[Check Credentials]
    C -->|Permission| E[Skip Affected Checks]
    C -->|Network| F[Implement Retry Logic]
    C -->|Rate Limit| G[Wait and Retry]
    C -->|Resource Not Found| H[Mark as NEED_REVIEW]
    C -->|API Error| I[Log and Continue]
    
    D --> J{Credentials Valid?}
    J -->|Yes| K[Re-authenticate]
    J -->|No| L[Exit with Auth Error]
    K --> M[Resume Operation]
    
    E --> N[Update Error Count]
    N --> O[Continue with Next Check]
    
    F --> P{Retry Count < Max?}
    P -->|Yes| Q[Increment Counter]
    P -->|No| R[Mark Check Failed]
    Q --> S[Wait Exponential Backoff]
    S --> T[Retry Operation]
    T --> U{Success?}
    U -->|Yes| M
    U -->|No| F
    
    G --> V[Wait Rate Limit Period]
    V --> W[Retry Request]
    W --> X{Success?}
    X -->|Yes| M
    X -->|No| G
    
    H --> Y[Add Review Note]
    Y --> O
    
    I --> Z[Update Error Summary]
    Z --> O
    
    L --> END1[Exit Code 4]
    R --> AA[Log Failure]
    AA --> O
    
    M --> BB[Update Success Count]
    O --> BB
    BB --> CC[Continue Processing]
    
    style A fill:#ffcdd2
    style CC fill:#c8e6c9
    style END1 fill:#ffcdd2
```

## Parallel Execution Coordination

```mermaid
flowchart TD
    A[Initialize Thread Pool] --> B[Create Task Queue]
    B --> C[Queue IAM Tasks]
    B --> D[Queue S3 Tasks]
    B --> E[Queue EC2 Tasks]
    B --> F[Queue VPC Tasks]
    B --> G[Queue CloudTrail Tasks]
    B --> H[Queue KMS Tasks]
    
    C --> I[Thread 1 Available]
    D --> J[Thread 2 Available]
    E --> K[Thread 3 Available]
    F --> L[Thread 4 Available]
    G --> M[Thread 5 Available]
    H --> N[Thread 6 Available]
    
    I --> O[Execute IAM Check]
    J --> P[Execute S3 Check]
    K --> Q[Execute EC2 Check]
    L --> R[Execute VPC Check]
    M --> S[Execute CloudTrail Check]
    N --> T[Execute KMS Check]
    
    O --> U{Check Complete?}
    P --> V{Check Complete?}
    Q --> W{Check Complete?}
    R --> X{Check Complete?}
    S --> Y{Check Complete?}
    T --> Z{Check Complete?}
    
    U -->|Yes| AA[Store Result]
    U -->|Error| BB[Handle Error]
    V -->|Yes| CC[Store Result]
    V -->|Error| DD[Handle Error]
    W -->|Yes| EE[Store Result]
    W -->|Error| FF[Handle Error]
    X -->|Yes| GG[Store Result]
    X -->|Error| HH[Handle Error]
    Y -->|Yes| II[Store Result]
    Y -->|Error| JJ[Handle Error]
    Z -->|Yes| KK[Store Result]
    Z -->|Error| LL[Handle Error]
    
    AA --> MM[Return Thread to Pool]
    BB --> MM
    CC --> MM
    DD --> MM
    EE --> MM
    FF --> MM
    GG --> MM
    HH --> MM
    II --> MM
    JJ --> MM
    KK --> MM
    LL --> MM
    
    MM --> NN{More Tasks?}
    NN -->|Yes| OO[Get Next Task]
    NN -->|No| PP[Wait for Completion]
    OO --> QQ[Assign to Available Thread]
    QQ --> RR[Execute Task]
    RR --> U
    PP --> SS[All Threads Complete]
    SS --> TT[Shutdown Thread Pool]
    TT --> UU[Return Aggregated Results]
    
    style A fill:#e3f2fd
    style UU fill:#c8e6c9
```

## Export Format Decision Flow

```mermaid
flowchart TD
    A[Start Export Process] --> B[Check Export Flags]
    B --> C{Export Markdown?}
    C -->|Yes| D[Generate Markdown Report]
    C -->|No| E{Export JSON?}
    D --> E
    E -->|Yes| F[Generate JSON Export]
    E -->|No| G{Export CSV?}
    F --> G
    G -->|Yes| H[Generate CSV Export]
    G -->|No| I[No Additional Exports]
    H --> I
    I --> J[Create Output Directory]
    J --> K[Save All Files]
    K --> L[Generate File Manifest]
    L --> M[Display Export Summary]
    M --> N[Export Complete]
    
    style A fill:#e8f5e8
    style N fill:#c8e6c9
```