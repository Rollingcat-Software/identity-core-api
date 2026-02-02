# Server Providers Research - Identity Core API

## Architecture Overview

The Identity Core API has two distinct compute workloads:

1. **Identity Core API (Java/Spring Boot)** - Lightweight REST API, JWT auth, multi-tenancy, audit logging
   - Memory: 256MB-512MB JVM heap
   - No GPU required
   - Suitable for standard VPS

2. **Biometric Processor (FastAPI)** - Face detection, embedding extraction (VGG-Face/FaceNet512), liveness detection, quality assessment
   - Requires GPU for ML inference
   - Models: VGG-Face (2622-dim) or FaceNet512 (512-dim)
   - Communicates via HTTP on port 8001

```
┌────────────────────────────┐        ┌──────────────────────────────┐
│  Identity Core API (Java)  │──HTTP──│  Biometric Processor (FastAPI)│
│  VPS                       │ :8001  │  GPU Instance / Serverless    │
└────────────────────────────┘        └──────────────────────────────┘
               │                                    │
               ▼                                    │
     PostgreSQL + pgvector  ◄───────────────────────┘
     (Vector embeddings)
```

---

## VPS Providers (for Java API + Database)

| Provider | Plan | vCPUs | RAM | Storage | Transfer | Monthly Price |
|----------|------|-------|-----|---------|----------|---------------|
| **Hetzner** | CX22 | 2 | 4 GB | 40 GB NVMe | 20 TB | ~$4.00 |
| **Hetzner** | CX32 | 4 | 8 GB | 80 GB NVMe | 20 TB | ~$7.20 |
| **Contabo** | Cloud VPS 10 | 3 | 8 GB | 75 GB NVMe | Unlimited | $4.95 |
| **OVHcloud** | VPS 1 | 2 | 4 GB | 40 GB | Unlimited | $4.20 |
| **AWS Lightsail** | 4GB | 2 | 4 GB | 80 GB SSD | 4 TB | $20.00 |
| **AWS Lightsail** | 8GB | 2 | 8 GB | 160 GB SSD | 5 TB | $40.00 |
| **DigitalOcean** | Basic 4GB | 2 | 4 GB | 80 GB SSD | 4 TB | $24.00 |
| **DigitalOcean** | Basic 8GB | 4 | 8 GB | 160 GB SSD | 5 TB | $48.00 |
| **Linode/Akamai** | Shared 4GB | 2 | 4 GB | 80 GB SSD | 4 TB | $24.00 |
| **Vultr** | Cloud Compute | 2 | 4 GB | 80 GB NVMe | 3 TB | ~$24.00 |

### VPS Recommendation

**Hetzner CX22/CX32** offers the best price-performance at ~$4-7/mo (5-6x cheaper than US providers).
The Java API needs only 256-512MB JVM heap, so a 4GB VPS is sufficient with room for PostgreSQL.

---

## GPU Providers (for Biometric Processor)

### Dedicated GPU Instances (always-on)

| Provider | GPU | VRAM | vCPUs | RAM | Hourly | Monthly (730h) |
|----------|-----|------|-------|-----|--------|-----------------|
| **Vast.ai** | T4 | 16 GB | varies | varies | $0.10-0.20 | ~$73-146 |
| **RunPod** | RTX 3090 | 24 GB | -- | -- | ~$0.20 | ~$146 |
| **AWS g4dn.xlarge (Spot)** | T4 | 16 GB | 4 | 16 GB | ~$0.16 | ~$117 |
| **Hetzner GEX44** | RTX 4000 Ada | 20 GB | 14 | -- | -- | ~$194 |
| **RunPod** | T4 | 16 GB | -- | -- | $0.40 | ~$292 |
| **AWS g4dn.xlarge (On-Demand)** | T4 | 16 GB | 4 | 16 GB | $0.526 | ~$384 |
| **Google Cloud** | T4 (n1) | 16 GB | 4 | 15 GB | $0.55-0.75 | ~$400-550 |
| **Azure** | NC T4 v3 | 16 GB | 4 | 28 GB | ~$0.53 | ~$387 |
| **Google Cloud** | L4 (g2) | 24 GB | 4-8 | 16-32 GB | $0.67-0.85 | ~$490-620 |
| **AWS g5.xlarge** | A10G | 24 GB | 4 | 16 GB | $1.006 | ~$734 |
| **Lambda Cloud** | A6000 | 48 GB | -- | -- | $0.80 | ~$584 |
| **Hetzner GEX130** | RTX 6000 Ada | 48 GB | 24 | 128 GB | -- | ~$885 |

### Serverless GPU (pay-per-inference, scales to zero)

Best for bursty/low-volume workloads. You pay nothing when idle.

| Provider | GPU | Cost/sec | 10K req/mo (500ms each) | 100K req/mo |
|----------|-----|----------|------------------------|-------------|
| **Modal** | T4 | ~$0.000164 | ~$0.82 | ~$8 |
| **RunPod Serverless** | T4 | ~$0.00022 | ~$1.11 | ~$11 |
| **Replicate** | T4 | ~$0.00055 | ~$2.75 | ~$28 |
| **AWS SageMaker Serverless** | T4 | ~$0.00088 | ~$4.40 | ~$44 |

**Break-even**: Serverless becomes more expensive than dedicated GPU at ~200K-500K requests/month.

**Note**: Banana.dev shut down in March 2024.

---

## Recommended Configurations by Scale

| Scale | API Server | Biometric Processor | Est. Total |
|-------|-----------|---------------------|------------|
| **Dev/MVP** | Hetzner CX22 ($4) | RunPod/Modal Serverless | $5-15/mo |
| **Small prod** (<50K users) | Hetzner CX32 ($7) | RunPod Serverless | $10-50/mo |
| **Medium prod** (50-500K users) | Hetzner CX32 ($7) | Hetzner GEX44 ($194) | ~$200/mo |
| **Large prod** (500K+ users) | AWS/GCP VPS ($24-48) | AWS g4dn Spot + fallback | $150-400/mo |

---

## Key Decisions

### For the VPS (Java API)
- **Hetzner** for budget, **AWS Lightsail** if you want AWS ecosystem integration
- 4GB RAM is sufficient; 8GB gives headroom for PostgreSQL + Redis on same node

### For the Biometric Processor
- **T4 (16GB VRAM)** is the sweet spot for FaceNet512/VGG-Face inference
- Start with **serverless GPU** (Modal or RunPod) to minimize costs during development
- Move to **dedicated GPU** (Hetzner GEX44 or AWS Spot) when throughput demands it
- Avoid DigitalOcean GPU Droplets (only H100/H200, starts at $555/mo -- overkill)

### Serverless GPU Advantages for Biometrics
- Scale to zero during low-traffic periods (nights, weekends)
- No GPU management overhead
- Sub-second cold starts (RunPod FlashBoot: <200ms)
- Pay only for actual inference time
- Natural fit for the existing HTTP-based architecture (FastAPI service)

---

## Sources

- [Hetzner Cloud](https://www.hetzner.com/cloud) | [Hetzner GPU](https://www.hetzner.com/dedicated-rootserver/matrix-gpu/)
- [DigitalOcean Pricing](https://www.digitalocean.com/pricing/droplets) | [GPU Droplets](https://www.digitalocean.com/pricing/gpu-droplets)
- [AWS Lightsail](https://aws.amazon.com/lightsail/pricing/) | [EC2 G4/G5](https://aws.amazon.com/ec2/instance-types/g4/)
- [RunPod](https://www.runpod.io/pricing) | [Vast.ai](https://vast.ai/pricing) | [Lambda Cloud](https://lambda.ai/pricing)
- [Google Cloud GPUs](https://cloud.google.com/compute/gpus-pricing) | [Azure NC Series](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/gpu-accelerated/nc-family)
- [Replicate](https://replicate.com/pricing) | [Modal](https://modal.com/pricing) | [AWS SageMaker](https://aws.amazon.com/sagemaker/pricing/)

*Research date: February 2026*
