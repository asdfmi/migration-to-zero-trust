# Background of VPN

When ARPANET began operation in 1969, networks were infrastructure shared by a limited group of researchers.

During the 1970s and 80s, LANs centered on Ethernet proliferated, and corporate networks became self-contained on-premises internal infrastructure. The "inside of the network" in this era was largely established not as a result of deliberate defensive design, but because external parties simply could not reach it physically or technically.

However, when TCP/IP was adopted on ARPANET and the transition from NCP to TCP/IP was planned and executed, ARPANET transformed into "part of the Internet" that could interconnect with other networks. From this point, network boundaries came to be defined not by "whether entities belonged to the same building or organization" but by "whether communication could actually reach them."

In the 1990s, the privatization of NSFNET and the establishment of the commercial Internet commoditized IP reachability, and corporate networks became "entities that could be touched from outside." Simultaneously, the 1988 Morris Worm incident confronted organizations with the reality that "being connected itself becomes a risk."

The implementations that were widely adopted to address this contradiction were NAT and private addresses. While originally introduced to address issues like address exhaustion and operational challenges, they effectively solidified the assumption in operators' minds that "the inside is unreachable from the global Internet."

Thus, "inside and outside" became separated in implementation. Traditional VPN is understood as a technology that, without breaking this boundary assumption, allows only necessary communications to pass through to the inside as exceptions via encryption and authentication over public networks.

# Weaknesses of the Boundary Trust Model in Traditional VPN

Traditional VPN is a technology that extends boundary-based network design directly to remote connectivity. As a result, "before entry" and "after entry" are strongly separated by design. While strict authentication is performed at the entrance, once inside, communications become relatively unrestricted.

This structure has an inherent weakness. The moment the boundary is breached, attackers gain entry to the "privileged intranet" and can instantly acquire reachability to ranges never originally intended.

However, in the on-premises-centric era, this weakness was not prominent. The cost of getting inside was high, with physical entry to office buildings and use of managed devices being prerequisites, which strongly limited "entities that could exist inside." Therefore, the design assumption of "trusting the inside" did not significantly diverge from operational reality at the time.

# The Rise of Cloud

In the on-premises era, valuable assets were primarily placed on networks under the management of the same organization and same location, and even if one got inside, the design did not allow critical operations to be performed immediately. "Getting inside" and "being able to cause damage" were clearly separated.

Cloud reversed this relationship. With the proliferation of cloud services, computing resources and data became commonly placed outside the enterprise's physical internal network boundary (on cloud infrastructure), and access increasingly relied on Internet technologies (HTTPS and APIs) and logical controls. Configurations that allowed direct access to cloud resources without going through physical internal networks became commonplace. As a result, being reachable over the network ceased to be a special exception and became the normal mode of use.

Consequently, what one "could do" once inside increased dramatically. In the cloud, breaching authentication readily translates to exercising broad operational privileges, and once permitted, the scope of direct impact on data and infrastructure becomes large. Rather than reachability simply increasing, what changed was the structure: what you could reach now connected directly to value.

Traditional VPN's design was not inherently flawed; rather, the spread of cloud changed the assumptions on which it was founded. This is why Zero Trust came to be needed.

# Google's Arrival at Zero Trust

With the spread of cloud, the assumption of inside versus outside collapsed, and the cost-effectiveness of the boundary model centered on traditional VPN deteriorated rapidly. One of the companies that faced this problem earliest and most practically was Google.

Against the backdrop of a massive organization's decentralization and cloud-first infrastructure, Google found itself in a situation where designs premised on a "privileged intranet" could no longer hold. Furthermore, internal breaches became reality, forcing them to design with the assumption that boundaries would be breached.

The conclusion drawn from Google's experience was clear: do not use location or network inside/outside as the basis for trust. Access is always determined based on user and device identification, current state, and the target resource. Only with this determination as a premise can access control independent of boundaries be established.

# Zero Trust Migration

Migration to Zero Trust is not about replacing traditional VPN or existing network equipment with new products. Nor is "stopping traditional VPN" itself the goal.

In operations premised on traditional VPN, who, on which device, to which resource, under which conditions was accessing was collectively treated as "trust," and once the boundary was crossed, internal communications were relatively permitted. This ambiguous trust has become fixed as an implicit assumption through years of operation.

Zero Trust migration is the process of decomposing this implicit trust and redefining who, on which device, to which resource, under which conditions as explicit policy. The benefit gained here is that the moment you discard the inside/outside location label, "what you are trusting" becomes structurally exposed, allowing trust to be redeployed in minimal units.

In the initial stages of migration, what happens first is not control but visibility. By observing existing communications without breaking them, subjects, destinations, and communication patterns can be organized as facts.

Through this visibility, communications whose purpose or responsible party cannot be explained, access from devices with unknown state, and communications that have "just been passing through" for years are enumerated as non-compliant traffic. This enumeration is not mere inventory; it is also the work of visualizing paths attackers could use to move laterally and converting them into forms that can be eliminated.

Zero Trust migration is not about introducing new mechanisms, but about elevating communications that previously required no explanation into explainable specifications, one by one. And "communications that have become explainable" can be directly connected to least privilege, audit, and staged blocking.

# Where It Gets Stuck

Zero Trust migration gets stuck not because the technology is immature, but because the ambiguity that traditional VPN boundaries have concealed for years must be recovered as design.

In operations premised on traditional VPN, many communications have passed simply because they were "inside" or "used for work." As a result, who is using what for what purpose, and under what conditions it should be permitted, has accumulated not as design but as established fact.

In Zero Trust, this ambiguity cannot be pushed back to the boundary. Communications for which subject, device, target resource, and conditions cannot be articulated are exposed as "things whose meaning has not been settled" before control can even begin.

The work that occurs at this stage is the process of observing actual communications, matching them against which business processes they are tied to, and articulating "why it is necessary" one by one.

What causes stalls at this stage is not lack of technology, but that who will take on this accountability, and to what extent, has not been defined within the organization.

A role is needed that enters the field, connects actual communications with business context, and moves the design forward.

# References

A Brief History of the Internet
https://www.internetsociety.org/internet/history-internet/brief-history-internet/

Birth of the Commercial Internet
https://www.nsf.gov/impacts/internet

NIST SP 800-77 Rev.1 – Guide to IPsec VPNs
https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-77r1.pdf

NIST SP 800-207 – Zero Trust Architecture
https://nvlpubs.nist.gov/nistpubs/specialpublications/NIST.SP.800-207.pdf

BeyondCorp: A New Approach to Enterprise Security
https://www.usenix.org/system/files/login/articles/login_dec14_02_ward.pdf

BeyondCorp: Design to Deployment at Google
https://www.usenix.org/system/files/login/articles/login_spring16_06_osborn.pdf
