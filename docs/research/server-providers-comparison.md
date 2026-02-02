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

## Part 1: VPS Providers Comparison (EU and Turkey Focus)

### 1.1 Hostinger VPS (KVM-based, All Tiers)

All plans use AMD EPYC processors, NVMe SSD storage, and KVM virtualization with full root access.
Docker is fully supported (KVM-based). Free weekly backups, 1 Gbps network, snapshots included.

| Plan | vCPU | RAM | NVMe Storage | Bandwidth | Promo Price/mo | Renewal Price/mo |
|------|------|-----|-------------|-----------|----------------|------------------|
| KVM 1 | 1 | 4 GB | 50 GB | 4 TB | $4.99 | ~$7.99 |
| KVM 2 | 2 | 8 GB | 100 GB | 8 TB | $6.99 | ~$10.99 |
| KVM 4 | 4 | 16 GB | 200 GB | 16 TB | $9.99 | ~$15.99 |
| KVM 8 | 8 | 32 GB | 400 GB | 32 TB | $19.99 | ~$29.99 |

**Promo prices require 24-month prepayment.** Renewal prices are significantly higher.

**EU Data Center Locations (VPS):**
- Lithuania (Vilnius)
- Netherlands (Amsterdam)
- United Kingdom (London)
- Germany (Frankfurt) -- newer addition
- France -- available for cloud/shared hosting only, NOT VPS yet

**Other Locations:** USA (multiple), Brazil, India, Singapore, Indonesia

**Docker Support:** YES -- full KVM virtualization, install Docker freely.
**Managed K8s:** No. Self-managed only.

Sources: [Hostinger VPS Pricing](https://www.hostinger.com/pricing/vps-hosting) | [Hostinger VPS Locations](https://hostingadvices.co.uk/hostinger-vps-locations/) | [VPSBenchmarks](https://www.vpsbenchmarks.com/compare/hostinger)

---

### 1.2 Hetzner Cloud (Germany/Finland)

Best price-performance in Europe. All-inclusive pricing (traffic, IPv4/IPv6, DDoS, firewall included).
Docker fully supported. Hourly billing with monthly caps.

#### CX Series (Cost-Optimized, Shared vCPU) -- BEST VALUE, Germany/Finland only

| Plan | vCPU | RAM | NVMe | Traffic | Price/mo |
|------|------|-----|------|---------|----------|
| CX23 | 2 | 4 GB | 40 GB | 20 TB | **EUR 3.49** |
| CX33 | 4 | 8 GB | 80 GB | 20 TB | **EUR 5.49** |
| CX43 | 8 | 16 GB | 160 GB | 20 TB | **EUR 9.49** |
| CX53 | 16 | 32 GB | 320 GB | 20 TB | **EUR 17.49** |

#### CAX Series (ARM Ampere, Shared) -- Germany/Finland only

| Plan | vCPU | RAM | NVMe | Traffic | Price/mo |
|------|------|-----|------|---------|----------|
| CAX11 | 2 | 4 GB | 40 GB | 20 TB | EUR 3.79 |
| CAX21 | 4 | 8 GB | 80 GB | 20 TB | EUR 6.49 |
| CAX31 | 8 | 16 GB | 160 GB | 20 TB | EUR 12.49 |

#### CPX Series (AMD EPYC, Shared) -- All regions (incl. USA, Singapore)

| Plan | vCPU | RAM | NVMe | Traffic (EU) | Price/mo |
|------|------|-----|------|-------------|----------|
| CPX11 | 2 | 2 GB | 40 GB | 1 TB | EUR 4.99 |
| CPX21 | 3 | 4 GB | 80 GB | 2 TB | EUR 9.49 |
| CPX31 | 4 | 8 GB | 160 GB | 3 TB | EUR 16.49 |
| CPX41 | 8 | 16 GB | 240 GB | 4 TB | EUR 30.49 |

#### CCX Series (Dedicated vCPU) -- All regions

| Plan | vCPU | RAM | NVMe | Traffic (EU) | Price/mo |
|------|------|-----|------|-------------|----------|
| CCX13 | 2 | 8 GB | 80 GB | 1 TB | EUR 12.49 |
| CCX23 | 4 | 16 GB | 160 GB | 2 TB | EUR 24.49 |
| CCX33 | 8 | 32 GB | 240 GB | 3 TB | EUR 48.49 |

**Data Center Locations:**
- Germany: Falkenstein (FSN1), Nuremberg (NBG1)
- Finland: Helsinki (HEL1)
- USA: Ashburn (VA), Hillsboro (OR)
- Singapore

**DOES NOT have a Turkey data center.** Closest to Turkey: Helsinki (~2200km) or Nuremberg (~1800km).

**Docker Support:** YES -- full KVM, Docker/Podman/K8s all work.
**Managed K8s:** YES -- Hetzner offers managed Kubernetes clusters.

Sources: [Hetzner Cloud](https://www.hetzner.com/cloud) | [Hetzner Locations](https://docs.hetzner.com/cloud/general/locations/)

---

### 1.3 Contabo (Germany-based, Budget King)

Extremely generous RAM/storage for the price. VPS plans start at 8 GB RAM.
EU location assigned automatically (typically Germany or France).

| Plan | vCPU | RAM | NVMe / SSD | Port Speed | Traffic | Price/mo |
|------|------|-----|-----------|------------|---------|----------|
| Cloud VPS 10 | 4 | 8 GB | 75 GB / 150 GB | 200 Mbit/s | Unlimited | **EUR 4.50** (~$4.95) |
| Cloud VPS 20 | 6 | 12 GB | 100 GB / 200 GB | 300 Mbit/s | Unlimited | **EUR 7.00** (~$7.70) |
| Cloud VPS 30 | 8 | 24 GB | 200 GB / 400 GB | 600 Mbit/s | Unlimited | **EUR 14.00** (~$15.40) |
| Cloud VPS 40 | 12 | 48 GB | 250 GB / 500 GB | 800 Mbit/s | Unlimited | **EUR 25.00** |
| Cloud VPS 50 | 16 | 64 GB | 300 GB / 600 GB | 1 Gbit/s | Unlimited | **EUR 37.00** |

**EU Data Center Locations:**
- EU (auto-assigned -- Germany/France typically)
- UK
- Non-EU regions (USA, Asia, Australia) available for extra fee

**DOES NOT have a Turkey data center.**

**Docker Support:** YES -- KVM-based, full root access.
**Managed K8s:** No.

**Note:** Contabo has very generous specs for the price but lower port speeds (200-600 Mbit/s on entry plans) compared to Hetzner (1 Gbit/s on all plans). Performance benchmarks also show lower I/O than Hetzner.

Sources: [Contabo Pricing](https://contabo.com/en/pricing/) | [Contabo EU Locations](https://contabo.com/en/locations/europe/) | [VPSBenchmarks](https://www.vpsbenchmarks.com/compare/contabo)

---

### 1.4 OVHcloud (France-based)

Large EU provider with extensive European presence. Good network infrastructure.

| Plan | vCores | RAM | Storage | Bandwidth | Price/mo |
|------|--------|-----|---------|-----------|----------|
| VPS-1 | 1 | 2 GB | 20 GB SSD | 100 Mbps | ~$4.20 |
| VPS-2 | 4 | 8 GB | 75 GB SSD | 400 Mbps | ~$6.75 |
| VPS-3 | 6 | 12 GB | 100 GB NVMe | 1 Gbps | ~$12.75 |
| VPS-4 | 8 | 24 GB | 200 GB NVMe | 1.5 Gbps | ~$22.08 |
| VPS-5 | 12 | 48 GB | 300 GB NVMe | 2 Gbps | ~$34.34 |

**EU Data Center Locations:**
- France: Paris, Roubaix, Gravelines, Strasbourg
- Germany: Frankfurt
- Poland: Warsaw
- UK: London
- Under construction: Italy, Netherlands, Spain

**15+ Local Zones** available for VPS across EU cities.
**DOES NOT have a Turkey data center.**

**Docker Support:** YES -- KVM-based VPS.
**Managed K8s:** YES -- OVHcloud offers managed Kubernetes service.

Sources: [OVHcloud VPS](https://us.ovhcloud.com/vps/) | [OVHcloud Locations](https://us.ovhcloud.com/about/global-infrastructure/locations/)

---

### 1.5 Scaleway (France-based, EU-sovereign)

European-focused cloud with strong GDPR compliance. All data centers in EU.

#### Development Instances (Paris only, shared, best for dev/test)

| Plan | vCPU | RAM | Bandwidth | Price/mo |
|------|------|-----|-----------|----------|
| STARDUST1-S | 1 | 1 GB | 100 Mbps | ~EUR 0.11 (excl. IPv4) |
| DEV1-S | 2 | 2 GB | 200 Mbps | ~EUR 6.42 |
| DEV1-M | 3 | 4 GB | 300 Mbps | ~EUR 14.45 |
| DEV1-L | 4 | 8 GB | 400 Mbps | ~EUR 30.66 |

#### PLAY2 Instances (all regions)

| Plan | vCPU | RAM | Bandwidth | Price/mo |
|------|------|-----|-----------|----------|
| PLAY2-PICO | 1 | 2 GB | 100 Mbps | ~EUR 10.22 |
| PLAY2-NANO | 2 | 4 GB | 200 Mbps | ~EUR 19.71 |
| PLAY2-MICRO | 4 | 8 GB | 400 Mbps | ~EUR 39.42 |

#### Dedicated vCPU

| Plan | vCPU | RAM | Bandwidth | Price/mo |
|------|------|-----|-----------|----------|
| POP2-2C-8G | 2 | 8 GB | 400 Mbps | ~EUR 53.65 |

**Data Center Locations:**
- Paris (multiple AZs)
- Amsterdam
- Warsaw

**DOES NOT have a Turkey data center.** Warsaw is the closest to Turkey (~1600km).

**Docker Support:** YES -- full Linux instances, Docker works natively.
**Managed K8s:** YES -- Scaleway Kapsule (managed Kubernetes).

**Assessment:** Scaleway is significantly more expensive than Hetzner/Contabo for equivalent specs. EUR 30.66/mo for 4 vCPU / 8 GB RAM vs Hetzner CX33 at EUR 5.49/mo. Not competitive for budget-focused deployments.

Sources: [Scaleway Pricing](https://www.scaleway.com/en/pricing/virtual-instances/) | [Scaleway Locations](https://www.scaleway.com/en/docs/)

---

## Part 2: Turkish VPS Providers (Istanbul/Ankara Data Centers)

### 2.1 Turhost (Founded 2004, Turkish)

One of Turkey's longest-running hosting providers. Data centers at Turk Telekom Istanbul Gayrettepe (Tier 3 certified) and Ankara.

**VPS Features:**
- NVMe SAN storage, Intel Xeon E5 processors
- 100 Mbit dedicated connection per VPS
- Daily backups stored for 30 days ("Time Machine")
- cPanel/Plesk/DirectAdmin support (Turkish language)
- DDoS protection included

**Pricing:** Listed in Turkish Lira (TRY), varies by configuration. Prices exclude 20% VAT (KDV). Specific tier pricing requires visiting their site directly as it changes frequently with TRY exchange rates.

**Docker Support:** YES -- KVM-based VPS with root access. Docker can be installed manually.
**Managed K8s:** No.

**Strengths:** Local Turkish support, Turkish-language assistance, data sovereignty under KVKK law.
**Weaknesses:** Prices in TRY fluctuate with exchange rate; limited international connectivity compared to Hetzner/OVH.

Sources: [Turhost VPS](https://www.turhost.com/sunucu/vps-server/) | [Hostings.info Turkey](https://hostings.info/hosting/ratings/turkey)

---

### 2.2 Radore (Founded 2004, Istanbul)

Premium Turkish data center provider. Located at MetroCity - Levent, Istanbul.
Over 3,500 customers. 99.99% uptime guarantee. "Uptime Experts" branding.

**Cloud Server (RCD - Radore Cloud Datacenter):**
- Proxmox-based VPS solutions
- Portal-based management
- Scalable resources (CPU/RAM/storage)
- Tier 3 data center, 3,020 m2 space

**Pricing (approximate, from older source):**
- R-OnApp: 1 CPU, 1 GB RAM, 20 GB storage, unlimited bandwidth -- ~$8.78/mo
- R-Cloud: 1 CPU, 1 GB RAM, 20 GB storage, unlimited bandwidth -- ~$15.70/mo

**Note:** Radore uses quote-based pricing for larger configurations. Contact satis@radore.com for current rates.

**Docker Support:** YES -- Proxmox-based virtualization supports Docker.
**Managed K8s:** Not publicly listed. Offers managed services upon request.

**Strengths:** Enterprise-grade Turkish data center, good for compliance-sensitive workloads.
**Weaknesses:** Quote-based pricing is opaque; significantly more expensive than international providers.

Sources: [Radore](https://radore.com/) | [Radore RCD](https://radore.com/en/rcd)

---

### 2.3 Natro (Founded 1999, Part of team.blue)

Long-standing Turkish hosting provider, now part of the team.blue group (European hosting conglomerate).

**VPS Plans (XCloud):**

| Plan | vCPU | RAM | Storage |
|------|------|-----|---------|
| XCloud Mini | 1 | 1 GB | 20 GB SSD |
| ... (8 tiers) | ... | ... | ... |
| XCloud Ultra+ | 16 | 64 GB | 1 TB SSD |

**Features:**
- 100% SSD, full redundancy
- DDoS protection, free backup
- 1-click app installs (CMS, E-Commerce)
- OS options: AlmaLinux, Ubuntu, Debian, Windows Server 2019
- Monthly or annual billing
- 14-day refund policy

**Pricing:** Listed in TRY on their website. Significant new-customer discounts that expire on renewal.

**Docker Support:** YES -- KVM/VDS with root access. Docker installable.
**Managed K8s:** No.

Sources: [Natro VPS](https://www.natro.com/sunucu-kiralama/vps-cloud-server) | [Natro Review](https://www.websiteplanet.com/web-hosting/natro/)

---

### 2.4 Medianova (Founded 2005, Istanbul)

**NOT a VPS provider.** Medianova is a CDN and cloud security company.

- Largest CDN in Turkey, Middle East, and Africa
- 50+ PoPs in 21 countries, 11 PoPs in 3 Turkish cities
- 100% SSD Anycast network
- Pay-as-you-go: ~$0.04-$0.20/GB data transfer
- Enterprise customers: Turkcell, Vodafone, Hepsiburada

**Relevance:** Could be used as a CDN layer in front of the Identity Core API, but does NOT offer VPS/compute instances.

Sources: [Medianova](https://www.medianova.com/) | [CDN Planet](https://www.cdnplanet.com/cdns/medianova/)

---

### 2.5 DigitalOcean Istanbul -- NOT AVAILABLE

DigitalOcean does **NOT** have a data center in Istanbul or anywhere in Turkey as of February 2026.
A Turkey data center has been a popular community request (493+ votes) with "gathering feedback" status, but no announcement has been made.

DigitalOcean's closest region to Turkey is **Frankfurt, Germany** or **London, UK**.

Sources: [DigitalOcean Turkey Request](https://ideas.digitalocean.com/infrastructure/p/turkey-data-center) | [DO Locations](https://docs.digitalocean.com/platform/regional-availability/)

---

### 2.6 Hetzner Turkey -- NOT AVAILABLE

Hetzner does **NOT** have any data centers in Turkey.
Their locations are: Germany (Falkenstein, Nuremberg), Finland (Helsinki), USA (Ashburn, Hillsboro), Singapore.

Closest to Turkey: Nuremberg (~1800km), Helsinki (~2200km).

---

### 2.7 HostArmada (International, HAS Turkey/Istanbul location)

International provider with a data center in Istanbul, Turkey. Unmanaged VPS with full root access.

**VPS Plans:**

| Plan | vCPU | RAM | NVMe Storage | Bandwidth | Promo Price/mo |
|------|------|-----|-------------|-----------|----------------|
| Spark | 1 | 1 GB | 40 GB | 2 TB | $3.69 |
| Fusion | 4 | 8 GB | 160 GB | 6 TB | $10.74 |

**Features:**
- 17 Tbit/s DDoS protection
- Dedicated IPv4 with reverse DNS
- Free automated backups + manual snapshots
- 23 data centers worldwide (including Istanbul)
- 7-day money-back guarantee

**Docker Support:** YES -- full root access, KVM-based.
**Managed K8s:** No.

Sources: [HostArmada VPS](https://hostarmada.com/vps-hosting/) | [HostArmada Pricing](https://hostarmada.com/pricing/)

---

### 2.8 Other Notable Turkey VPS Providers

| Provider | Notes |
|----------|-------|
| **HOSTKEY** | International provider with VPS servers in Istanbul |
| **UltaHost** | Istanbul VPS available, fast servers |
| **LightNode** | Turkey VPS with Istanbul location |
| **PQ Hosting** | VPS in Turkey (Istanbul/Izmir) |
| **Serverspace** | International cloud provider, Turkey presence |
| **Hosting.com.tr** | Turkish domain registrar + hosting |
| **Isimtescil.net** | Founded 1998, Turkish registrar + hosting |
| **Atakdomain.com** | Founded 2003, Turkish hosting provider |

---

## Part 3: EU Providers with Good Turkey Proximity

### Proximity to Istanbul (approximate network latency)

| Location | Distance to Istanbul | Expected Latency |
|----------|---------------------|------------------|
| **Sofia, Bulgaria** | ~500 km | ~10-15 ms |
| **Bucharest, Romania** | ~600 km | ~10-15 ms |
| **Athens, Greece** | ~550 km | ~10-15 ms |
| **Warsaw, Poland** | ~1400 km | ~25-35 ms |
| **Frankfurt, Germany** | ~1800 km | ~35-50 ms |
| **Nuremberg, Germany** | ~1800 km | ~35-50 ms |
| **Amsterdam, Netherlands** | ~2200 km | ~45-60 ms |
| **Paris, France** | ~2300 km | ~45-65 ms |
| **Helsinki, Finland** | ~2200 km | ~40-55 ms |

**Key Insight:** No major budget VPS provider (Hetzner, Contabo, OVH, Scaleway) has data centers in Romania, Bulgaria, or Greece. The closest EU locations to Turkey are:
- **OVHcloud Warsaw** (Poland) -- ~25-35ms to Istanbul
- **Scaleway Warsaw** (Poland) -- ~25-35ms to Istanbul
- **Hetzner Nuremberg/Falkenstein** (Germany) -- ~35-50ms to Istanbul
- **Hostinger Lithuania** (Vilnius) -- ~30-40ms to Istanbul

For Turkey-located servers, **HostArmada Istanbul** or local Turkish providers (Turhost, Natro, Radore) are the only options.

---

## Part 4: Docker Support Analysis

### Do ALL VPS providers support Docker?

**Short answer: YES, if they use KVM or full virtualization.** All providers listed in this document support Docker.

### The Docker Compatibility Rule

| Virtualization Type | Docker Support | Notes |
|--------------------|---------------|-------|
| **KVM** | FULL support | All providers above use KVM |
| **Xen HVM** | FULL support | Rare in 2026 |
| **OpenVZ 7+** | Partial | Needs host-level config, unreliable |
| **OpenVZ 6** | NO support | Cannot run Docker at all |
| **LXC/LXD** | Limited | Nested containers, not recommended |

### Provider-by-Provider Docker Status

| Provider | Virtualization | Docker? | Notes |
|----------|---------------|---------|-------|
| Hostinger | KVM | YES | Full support, Docker templates available |
| Hetzner | KVM | YES | Full support, Docker CE preinstallable |
| Contabo | KVM | YES | Full support |
| OVHcloud | KVM | YES | Full support |
| Scaleway | KVM | YES | Full support, managed K8s (Kapsule) |
| Turhost | KVM | YES | Manual install required |
| Radore | Proxmox/KVM | YES | Full support |
| Natro | KVM/VDS | YES | Manual install required |
| HostArmada | KVM | YES | Full support |

**WARNING:** Some ultra-cheap VPS providers (not listed here) still use OpenVZ 6/7, which does NOT reliably support Docker. Always verify the virtualization technology is KVM before purchasing a VPS for Docker workloads.

### Managed Kubernetes Options

| Provider | Service | Notes |
|----------|---------|-------|
| Hetzner | Managed K8s | Affordable, EU-only |
| OVHcloud | Managed K8s | EU data centers, GDPR-compliant |
| Scaleway | Kapsule | Paris/Amsterdam/Warsaw |
| DigitalOcean | DOKS | No Turkey location |
| None of the Turkish providers | -- | No managed K8s offerings found |

---

## Part 5: Price Comparison Matrix (2-4 vCPU, 4-8 GB RAM)

### Target: VPS suitable for Java API + PostgreSQL (4-8 GB RAM range)

| Provider | Plan | vCPU | RAM | Storage | Price/mo | Location Options |
|----------|------|------|-----|---------|----------|-----------------|
| **Hetzner** | CX23 | 2 | 4 GB | 40 GB NVMe | **EUR 3.49** | DE, FI |
| **Hetzner** | CX33 | 4 | 8 GB | 80 GB NVMe | **EUR 5.49** | DE, FI |
| **Contabo** | VPS 10 | 4 | 8 GB | 75 GB NVMe | **EUR 4.50** | EU (auto) |
| **OVHcloud** | VPS-1 | 1 | 2 GB | 20 GB SSD | ~$4.20 | EU (13+ cities) |
| **OVHcloud** | VPS-2 | 4 | 8 GB | 75 GB SSD | ~$6.75 | EU (13+ cities) |
| **Hostinger** | KVM 1 | 1 | 4 GB | 50 GB NVMe | $4.99* | NL, LT, UK, DE |
| **Hostinger** | KVM 2 | 2 | 8 GB | 100 GB NVMe | $6.99* | NL, LT, UK, DE |
| **HostArmada** | Fusion | 4 | 8 GB | 160 GB NVMe | $10.74* | **Istanbul**, EU, US |
| **Scaleway** | DEV1-M | 3 | 4 GB | -- | ~EUR 14.45 | Paris |
| **Scaleway** | DEV1-L | 4 | 8 GB | -- | ~EUR 30.66 | Paris |

*Promo pricing with annual/multi-year commitment

### Best Value Rankings (for EU deployment)

1. **Hetzner CX33** -- EUR 5.49/mo for 4 vCPU, 8 GB RAM, 80 GB NVMe, 20 TB traffic (Germany/Finland)
2. **Contabo VPS 10** -- EUR 4.50/mo for 4 vCPU, 8 GB RAM, 75 GB NVMe, unlimited traffic (EU)
3. **OVHcloud VPS-2** -- ~$6.75/mo for 4 vCores, 8 GB RAM, 75 GB SSD (EU wide)
4. **Hostinger KVM 2** -- $6.99/mo for 2 vCPU, 8 GB RAM, 100 GB NVMe (EU)
5. **Hetzner CX23** -- EUR 3.49/mo for 2 vCPU, 4 GB RAM, 40 GB NVMe (if 4 GB is enough)

### Best Value for Turkey Proximity

1. **HostArmada Fusion (Istanbul)** -- $10.74/mo, 4 vCPU, 8 GB RAM, in Istanbul itself (~0-5ms)
2. **Hetzner CX33 (Nuremberg)** -- EUR 5.49/mo, 4 vCPU, 8 GB RAM (~35-50ms to Istanbul)
3. **OVHcloud VPS-2 (Warsaw)** -- ~$6.75/mo, 4 vCores, 8 GB RAM (~25-35ms to Istanbul)
4. **Turhost/Natro (Istanbul)** -- Pricing in TRY, check current rates (~0-5ms, local)
5. **Hostinger KVM 2 (Lithuania)** -- $6.99/mo, 2 vCPU, 8 GB RAM (~30-40ms to Istanbul)

---

## Part 6: GPU Providers (for Biometric Processor)

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

---

## Part 7: Recommended Configurations by Scale

| Scale | API Server | Biometric Processor | Est. Total |
|-------|-----------|---------------------|------------|
| **Dev/MVP** | Hetzner CX23 (EUR 3.49) | RunPod/Modal Serverless | $5-15/mo |
| **Small prod** (<50K users) | Hetzner CX33 (EUR 5.49) | RunPod Serverless | $10-50/mo |
| **Small prod (Turkey)** | HostArmada Istanbul ($10.74) | RunPod Serverless | $12-55/mo |
| **Medium prod** (50-500K users) | Hetzner CX33 (EUR 5.49) | Hetzner GEX44 ($194) | ~$200/mo |
| **Large prod** (500K+ users) | AWS/GCP VPS ($24-48) | AWS g4dn Spot + fallback | $150-400/mo |

---

## Part 8: Key Decisions

### For the VPS (Java API)
- **Hetzner CX33** is the clear winner for EU: EUR 5.49/mo for 4 vCPU, 8 GB RAM, 80 GB NVMe
- **Contabo VPS 10** is a close second at EUR 4.50/mo with more RAM but lower I/O performance
- **HostArmada Istanbul** if Turkey data residency is required (~$10.74/mo)
- 4 GB RAM is sufficient for the API alone; 8 GB gives headroom for PostgreSQL + Redis on same node
- Avoid Scaleway for VPS -- 3-6x more expensive than Hetzner for comparable specs

### For Turkey-Specific Deployments
- **Data residency under KVKK:** Use HostArmada Istanbul, Turhost, or Natro
- **Best latency to Turkey from EU:** OVHcloud Warsaw or Scaleway Warsaw (~25-35ms)
- **Best price near Turkey:** Hetzner Nuremberg at EUR 5.49/mo (~35-50ms latency)
- **Local Turkish providers** (Turhost, Natro, Radore) are more expensive and have less transparent pricing, but offer Turkish-language support and KVKK compliance

### For the Biometric Processor
- **T4 (16GB VRAM)** is the sweet spot for FaceNet512/VGG-Face inference
- Start with **serverless GPU** (Modal or RunPod) to minimize costs during development
- Move to **dedicated GPU** (Hetzner GEX44 or AWS Spot) when throughput demands it

### Docker Considerations
- ALL providers in this comparison support Docker (all use KVM)
- Avoid any provider using OpenVZ (some ultra-budget providers still do)
- For managed container orchestration, Hetzner K8s or OVHcloud K8s are the most affordable EU options

---

## Sources

### VPS Providers
- [Hostinger VPS Pricing](https://www.hostinger.com/pricing/vps-hosting) | [Hostinger Locations](https://hostingadvices.co.uk/hostinger-vps-locations/)
- [Hetzner Cloud](https://www.hetzner.com/cloud) | [Hetzner Locations](https://docs.hetzner.com/cloud/general/locations/)
- [Contabo Pricing](https://contabo.com/en/pricing/) | [Contabo EU](https://contabo.com/en/locations/europe/)
- [OVHcloud VPS](https://us.ovhcloud.com/vps/) | [OVHcloud Locations](https://us.ovhcloud.com/about/global-infrastructure/locations/)
- [Scaleway Pricing](https://www.scaleway.com/en/pricing/virtual-instances/)

### Turkish Providers
- [Turhost VPS](https://www.turhost.com/sunucu/vps-server/)
- [Radore Data Center](https://radore.com/) | [Radore RCD](https://radore.com/en/rcd)
- [Natro VPS](https://www.natro.com/sunucu-kiralama/vps-cloud-server)
- [Medianova CDN](https://www.medianova.com/)
- [HostArmada VPS](https://hostarmada.com/vps-hosting/) | [HostArmada Pricing](https://hostarmada.com/pricing/)

### Turkey VPS Market
- [Best Turkey VPS 2026 - HostAdvice](https://hostadvice.com/vps/turkey/)
- [Turkey VPS Ratings - Hostings.info](https://hostings.info/hosting/ratings/best-vpsvds-hosting-providers-in-turkey)
- [DigitalOcean Turkey Request](https://ideas.digitalocean.com/infrastructure/p/turkey-data-center)

### GPU Providers
- [Hetzner GPU](https://www.hetzner.com/dedicated-rootserver/matrix-gpu/)
- [RunPod](https://www.runpod.io/pricing) | [Vast.ai](https://vast.ai/pricing) | [Lambda Cloud](https://lambda.ai/pricing)
- [Modal](https://modal.com/pricing) | [Replicate](https://replicate.com/pricing)
- [AWS EC2 G4/G5](https://aws.amazon.com/ec2/instance-types/g4/) | [AWS SageMaker](https://aws.amazon.com/sagemaker/pricing/)
- [Google Cloud GPUs](https://cloud.google.com/compute/gpus-pricing) | [Azure NC Series](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/gpu-accelerated/nc-family)

### Docker/Virtualization
- [KVM vs OpenVZ for Docker](https://petrosky.io/kvm-vps-vs-openvz-2025/)
- [Docker VPS Hosting - HostAdvice](https://hostadvice.com/docker-hosting/docker-vps-hosting/)
- [VPSBenchmarks](https://www.vpsbenchmarks.com/)

*Research date: February 2026*
