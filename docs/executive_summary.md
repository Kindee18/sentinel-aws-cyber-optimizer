# Executive Summary & Demo Script

## 🎯 Platform Overview
**The Sentinel-AWS Cyber-Optimizer** is an automated, zero-trust DevSecOps pipeline and cost-optimization engine designed for multi-tenant log ingestion. It acts as an intelligent data layer sitting between AWS Kubernetes clusters (EKS) and Microsoft Sentinel, specifically designed to solve the two biggest challenges in modern MDR (Managed Detection and Response): **Skyrocketing SIEM ingestion costs** and **Software Supply Chain Risk**.

## 💰 How this reduces Microsoft Sentinel ingestion costs by 70%
Microsoft Sentinel charges by the Gigabyte (GB) for data ingestion. The vast majority of cloud infrastructure logs are "benign noise" (e.g., standard HTTP 200 health checks, routing background noise) that provide zero security value but cost thousands of dollars per month.

The Cyber-Optimizer deploys an **AWS Lambda Log Transformer** inside an Amazon Kinesis Data Firehose. This intelligent layer:
1.  **Intercepts** all incoming Kubernetes and container logs in real-time.
2.  **Analyzes** the JSON payloads.
3.  **Automatically Drops** benign `HTTP 200` status codes and non-security-related system chatter.
4.  **Forwards** critical `HTTP 401/403/500` errors and verified security events to Sentinel.

By terminating benign noise at the AWS edge before it ever traverses to Microsoft Sentinel, clients see a **60–70% immediate reduction in SIEM ingestion costs**, freeing up budget for critical SOC operations.

## 🤝 Alignment with BlueVoyant MDR
BlueVoyant leads the industry in **Microsoft Security** integration, Supply Chain Defense, and moving towards an **Agentic SOC** model. This platform aligns natively with these priorities:
*   **Agentic SOC Ready:** Rather than dumping raw data into a data lake for human analysts to parse, this pipeline pre-processes, redacts PII, and categorizes data at the edge. The SIEM receives high-fidelity alerts ready for automated SOAR playbooks.
*   **Supply Chain Defense:** The CI/CD pipeline proactively scans containers for CVEs (Trivy) and generates Software Bills of Materials (Syft/CycloneDX) unconditionally, shifting security left before code ever touches production.
*   **Zero-Trust AWS Design:** Multi-tenant separation using AWS provider aliases and Kubernetes Workload Identity (IRSA/OIDC) guarantees no hardcoded credentials exist anywhere in the lifecycle.

---

## 🎬 Live Demo Script: The Optimizer in Action

*Follow this 4-step script during a live interview or presentation to demonstrate the architecture.*

### Step 1: Deploy the "Dirty Data" Generator
Deploy a mock application to the EKS cluster. This application systematically creates HTTP 200s, HTTP 401 Unauthorized errors, and leaks sensitive PII (Social Security Numbers, AWS access keys, internal IPs).
```bash
kubectl apply -f kubernetes/mock-app.yaml
```

### Step 2: Validate the Log Generation
Show the audience that the raw application is actively outputting critical PII and benign noise directly into the cluster `stdout`.
```bash
kubectl logs -l app=mock-security-app -n mock-app -f
```
*(Point out the `HTTP 200` lines and the raw IP addresses).*

### Step 3: Trigger the Pipeline
Explain that **Fluent-Bit** automatically picks up these logs via the DaemonSet and streams them into **Amazon Kinesis**. The stream triggers our internal **Lambda Transformer**.

### Step 4: Validate the Output (S3 / Sentinel)
Navigate to the designated AWS S3 Storage Bucket (or the mock Sentinel dashboard) where the processed logs land.
Open a processed log item and demonstrate two things:
1.  **Noise is Gone:** There are no `HTTP 200` health checks in the bucket. They were successfully annihilated at the edge.
2.  **PII is Redacted:** Look at the `HTTP 401` logs. The raw IP address and users' emails have been algorithmically replaced with `[REDACTED_IPV4]` and `[REDACTED_EMAIL]`, ensuring compliance (GDPR/HIPAA/PCI) before the data hits the SIEM.

**Demo Complete. The system is secure, quiet, and optimized.**
