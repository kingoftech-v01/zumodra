# Services (Marketplace) App

## Overview

The Services app powers Zumodra's freelance marketplace, enabling providers to list services, clients to post jobs, and managing the full lifecycle from proposal to contract completion with secure escrow payments.

## Key Features

### Completed Features

- **Service Listings**: Create and manage service offerings
- **Service Discovery**: Search and filter services
- **Provider Profiles**: Freelancer profiles with portfolios
- **Proposals System**: Submit and manage proposals
- **Contract Management**: Project contracts with milestones
- **Escrow Payments**: Stripe Connect-powered secure payments
- **Project Tracking**: Work delivery and acceptance workflow
- **Dispute System**: Evidence-based dispute resolution

### In Development

- **Advanced Search**: Geospatial filtering with PostGIS
- **Rating System**: Verified ratings post-project completion
- **Messaging Integration**: In-context chat with clients
- **Portfolio Management**: GitHub/Behance/Dribbble integration
- **Subscription Services**: Recurring service packages

## Architecture

### Models

| Model | Description | Key Fields |
|-------|-------------|------------|
| **Service** | Service listings | title, description, category, rate, duration, provider |
| **ServiceCategory** | Service categories | name, parent, icon, order |
| **Proposal** | Job proposals | service, project, provider, client, amount, timeline, status |
| **Contract** | Project contracts | proposal, terms, milestones, total_amount, status |
| **Milestone** | Payment milestones | contract, description, amount, due_date, status |
| **Deliverable** | Work deliveries | milestone, file, description, submitted_at |
| **Dispute** | Disputes | contract, filed_by, reason, evidence, resolution, status |
| **Review** | Service reviews | contract, reviewer, rating, comment, verified |

### Views

**Service Management:**
- `ServiceListView` - Browse services
- `ServiceDetailView` - Service details
- `ServiceCreateView` - Create service
- `ServiceEditView` - Edit service
- `MyServicesView` - Provider's services

**Proposals & Contracts:**
- `ProposalCreateView` - Submit proposal
- `ProposalListView` - View proposals
- `ContractDetailView` - Contract dashboard
- `MilestoneSubmitView` - Submit deliverables
- `MilestoneApproveView` - Accept work

**Marketplace:**
- `MarketplaceHomeView` - Marketplace landing
- `ProviderProfileView` - Provider profile
- `ClientDashboardView` - Client dashboard

### URL Structure

```python
frontend:services:service_list
frontend:services:service_detail (pk)
frontend:services:service_create
frontend:services:proposal_create (service_pk)
frontend:services:contract_detail (pk)
frontend:services:marketplace_home
```

## Integration Points

- **Finance**: Escrow payments, Stripe Connect
- **Accounts**: Provider/client profiles, trust scores
- **Messages**: In-contract messaging
- **ATS**: Freelance recruitment circuit
- **HR Core**: Contractor management
- **Notifications**: Project updates

## External Services

- **Stripe Connect**: Escrow and payouts
- **PostGIS**: Geospatial service search
- **Storage**: S3 for deliverables

## Future Improvements

### High Priority

1. **Geospatial Search**
   - "Services near me" filtering
   - Distance-based sorting
   - Location-based pricing
   - Service area radius

2. **Verified Rating System**
   - Only completed project ratings
   - Multi-criteria ratings
   - Response to reviews
   - Trust score integration

3. **Advanced Matching**
   - AI skill matching
   - Compatibility scoring
   - Auto-suggest providers
   - Smart recommendations

4. **Portfolio Integration**
   - GitHub repository verification
   - Behance project imports
   - Dribbble integration
   - Custom portfolio builder

5. **Subscription Services**
   - Recurring packages
   - Retainer agreements
   - Auto-billing
   - Package tiers

### Medium Priority

6. **Service Packages**: Bundled services at discounted rates
7. **Team Services**: Multi-provider collaborations
8. **Service Templates**: Pre-configured service offerings
9. **API Integration**: Allow external service bookings
10. **Mobile Booking**: Mobile-optimized booking flow

### Low Priority

11. **Video Pitches**: Video proposals from providers
12. **Live Chat**: Real-time client-provider chat
13. **Service Analytics**: Performance metrics for providers

## Testing

Target: 90%+ coverage

```
tests/
├── test_services_models.py
├── test_proposals.py
├── test_contracts.py
├── test_escrow.py
└── test_disputes.py
```

## Security

- Escrow funds held securely
- Dispute evidence validation
- Review authenticity checks
- Payment fraud detection

---

**Last Updated:** January 2026
**Status:** Production
