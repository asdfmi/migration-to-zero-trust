# Background of VPN

In the on-premises era, a corporate network's "inside/outside" was not an idea but the management boundary itself.
Companies owned servers, wiring, routers, and firewalls, and could identify who configured them and who touched them.
On the other hand, the Internet side was a collection of third parties, so operational discipline and responsibility could not be shared.

In that era, the "inside" was not safe; communications and identities were predictable.
In addition, because it relied on leased lines and limited connection points, the cost of gaining reachability from outside to inside was high,
and the mere fact of being reachable functioned as a weak form of authentication.

However, with the spread of ISPs and the maturation of routing, global connectivity expanded rapidly.
As symbolized by IPv4 exhaustion, reachability shifted from a scarce resource to a commodity,
and the fact of "being reachable" could no longer substitute for trust.

For the first time, there arose a need to artificially recreate the "inside" that had been lost on public networks.
VPNs emerged as the technology to answer this, layering authentication and encryption on top of reachability
and explicitly constructing what had once existed implicitly.

# Weaknesses of VPN

VPNs were effective at recreating the "inside" lost on public networks.
But their design, in many cases, strongly separates "before entry" from "after entry."

At the entrance, strict checks are performed using keys, certificates, and authentication,
but once connected to the VPN, internal traffic becomes relatively free.
This is not a technical constraint so much as the result of extending the perimeter defense model as-is.

The problem with this structure is exposed the moment the boundary is breached.
When VPN credentials are leaked or endpoints are compromised,
attackers step into a "privileged intranet" and quickly gain reachability beyond the intended scope.

What matters is not that "the VPN was broken,"
but that the design still trusts the inside.

VPNs can control reachability,
but they do not guarantee least privilege or legitimacy of traffic after entry.
This structural weakness becomes the starting point of the later shift to Zero Trust.

# The Rise of Cloud

In 2006, AWS launched S3 (March) and EC2 (August beta),
shifting compute and storage from "ownership" to "use only what you need."
Without buying servers, environments could be brought up in minutes, with no upfront investment.
That flexibility and speed were embraced with strong enthusiasm in enterprise IT.

Meanwhile, VPNs had been effective before that era
as a technology to recreate the "inside" lost on public networks.
Their design assumes strict entrance control and a perimeter model that relatively trusts the inside.

This structural weakness itself existed before the cloud era.
But at the time, assets to protect were concentrated in the corporate LAN,
and the cost of external compromise was high, so in practice it did not become a major problem.

The spread of cloud overturned this premise.
Compute resources and data were no longer confined inside the boundary,
and Internet reachability and credentials became the direct entry points to high-value assets.

As a result, the VPN property of "breach the entrance = broad reachability inside" shifted
from a theoretical defect to a practical attack surface.
This was not because VPN was inferior, but a side effect of cloud inverting the cost-benefit of attack and defense.

VPNs can control reachability,
but they do not guarantee least privilege or legitimacy of traffic after entry.
This limitation forces a rethinking of boundary trust itself
and becomes the starting point for the later move toward Zero Trust design.

# Zero Trust Reached by Google

With the rise of cloud, the assumption of inside vs. outside collapsed,
and the cost-effectiveness of the VPN-centered perimeter model rapidly deteriorated.
One of the companies that faced this earliest and most realistically was Google.

Against the backdrop of a huge distributed organization and cloud-first infrastructure,
Google found that a design premised on a "privileged intranet" could no longer hold.
Moreover, internal compromise became a reality,
forcing design with the assumption that boundaries will be breached.

From this experience, Google's conclusion was clear.
Do not base trust on location or network boundaries.
Access must always be judged based on the user and device identity,
their state at that moment, and the resource being accessed.

This is the Google-style Zero Trust design later published as BeyondCorp.
What is important here is that Zero Trust is not a new security product,
but a design consequence of discarding boundary trust that no longer paid off in the cloud era.

Google did not replace VPNs.
It decomposed the "trust" that VPNs had implicitly carried
and redistributed it into authentication, authorization, encryption, and visibility.
As a result, the "privileged intranet" became unnecessary.

# Zero Trust Migration

Migrating to Zero Trust is not about replacing VPNs or existing network devices
with new products.
Nor is "stopping VPNs" itself the goal.

In traditional VPN-based operations,
reachability, location, and network boundaries were bundled together as "trust,"
and once inside the boundary, internal traffic was relatively permitted.
This ambiguous trust has been fixed as an implicit assumption over years of operations.

Zero Trust migration is the process of decomposing that implicit trust
and redefining, as explicit policy, who is accessing which resource, from which device,
and under what conditions.
The benefit gained here is that the moment you discard the inside/outside label,
"what you trust" becomes visible as a structure,
and you can reassign trust at the smallest unit.

The difficulty is not in technical sophistication.
It lies in forcibly exposing the ambiguous reality that VPNs have hidden.
But for the same reason, once you can make it explicit,
it becomes the foundation for defense not dependent on boundaries.

In the early stages of migration, the first thing to do is not control but visibility.
By observing existing traffic without breaking it,
the facts of who connects, from where, and how are exposed.

With this visibility,
traffic without an explainable purpose or owner,
access from devices with unknown state,
and traffic that has long been "allowed for now"
are listed as non-compliant traffic.
This listing is not just an inventory;
it is also the work of visualizing lateral movement paths one by one
and converting them into items that can be eliminated.

Zero Trust migration is not about introducing a new mechanism,
but about raising previously unexplained communications
into specifications that can be explained one by one.
And "explainable communications" can then connect directly
to least privilege, auditing, and staged blocking.

# Where It Gets Stuck

Zero Trust migration gets stuck not because the technology is immature.
It gets stuck because the boundary called VPN has hidden ambiguity for years,
and that ambiguity must be recovered as design.

In VPN-based operations, many communications have been allowed
simply because "it is inside" or "it is used for business."
As a result, who uses what for what purpose,
and under what conditions it should be allowed,
have accumulated as facts rather than design.

In Zero Trust, this ambiguity cannot be pushed back to the boundary.
Traffic that cannot be expressed in terms of actor, device, resource, and conditions
is exposed, even before control, as "not yet given meaning."

The work that occurs here is not tool adoption or policy writing.
It is the process of observing actual traffic,
matching it to which business process and which step it belongs to,
and articulating "why it is necessary" one by one.

What is important is that this process is not a one-time migration task.
Business changes, systems grow and shrink,
and new communications continue to occur.
The accountability that VPNs had shouldered at the boundary
must be re-assumed as design each time in Zero Trust.

Therefore Zero Trust migration cannot become a project that ends.
It becomes operations themselves, including continuous observation,
meaning-making, and adjustment to maintain operations without boundaries.

The sticking point at this stage is not a lack of technology or products,
but that within the organization it is not defined
who will take on this accountability and to what extent.

For the first time, a role is needed to enter the field
and move the design forward by tying real traffic to business context.
The role of the FDE (Forward Deployed Engineer)
is optimal for resolving this structural bottleneck.

---

# VPN の背景

オンプレ中心の時代、企業ネットワークの「内／外」は思想ではなく管理境界そのものだった。
企業はサーバ・配線・ルータ・FWを自ら保有し、誰が設定し、誰が触れるかを把握できた。
一方、インターネット側は第三者の集合で、運用規律も責任主体も共有できない。

この時代において「内側」は安全だったのではなく、通信と主体が予測可能だった。
加えて、専用線や限定的な接続点に依存していたため、外部から内側への到達性の獲得コストは高く、
到達できること自体が結果的に弱い認証として機能していた。

しかし、ISPの普及とルーティングの成熟により、世界規模での接続性が急速に拡大する。
IPv4枯渇が象徴するように、到達性は希少資源からコモディティへと変わり、
「到達できる」という事実はもはや信頼の代替にならなくなった。

ここで初めて、公共ネットワーク上で失われた「内側」を人工的に再現する必要が生じる。
VPNはこの要請に応える技術として、到達性の上に認証と暗号を重ね、
かつて暗黙に成立していた内側を明示的に構築する手段として登場した。

# VPN の弱点

VPNは、公共ネットワーク上で失われた「内側」を再現するための有効な技術だった。
しかしその設計は、多くの場合「入る前」と「入った後」を強く分離する。

入口では、鍵・証明書・認証などにより厳密なチェックを行う一方、
一度VPNに接続すると、内側の通信は相対的に自由になる。
これは技術的制約というより、境界防御モデルをそのまま引き延ばした結果である。

この構造の問題は、境界が破られた瞬間に露呈する。
VPN資格情報の漏洩や端末侵害が起きると、
攻撃者は「特権的イントラネット」に足を踏み入れ、
本来想定されていなかった範囲への到達性を一気に獲得する。

重要なのは、問題の本質が
「VPNが破られた」ことではなく、
「内側を信頼してしまう設計が残っている」点にあることだ。

VPNは到達性を制御できても、
内側に入った後の最小権限や通信の正当性までは保証しない。
この構造的弱点が、後にZero Trustへと設計思想が転換される出発点になる。

# Cloudの台頭

2006年、AWSはS3（3月）とEC2（8月・ベータ）を公開し、
計算資源と保存資源を「所有」から「必要な分だけ使う」ものへと変えた。
サーバを買わず、数分で環境を立ち上げられ、初期投資は不要。
この柔軟性と速度は、企業ITに強い熱狂をもって受け入れられた。

一方で、VPNはそれ以前の時代に、
公共ネットワーク上で失われた「内側」を再現する技術として有効に機能してきた。
その設計は、厳密な入口制御と、内側を相対的に信頼する境界モデルを前提としている。

この構造的弱点自体は、Cloud以前から存在していた。
しかし当時は、守るべき資産が社内LANに集中し、
外部からの侵害コストも高かったため、実務上は大きな問題にならなかった。

Cloudの普及は、この前提を根本から崩した。
計算資源やデータは境界内に閉じなくなり、
インターネット到達性と資格情報が、そのまま高価値資産への入口になる。

その結果、VPNの「入口突破＝内側への広範な到達性」という性質は、
理論上の欠陥から、現実的な攻撃面へと変わった。
これはVPNが劣っていたからではなく、
Cloudによって攻撃と防御の費用対効果が反転した副作用である。

VPNは到達性を制御できても、
内側に入った後の最小権限や通信の正当性までは保証しない。
この限界が、境界信頼そのものを再考する必要性を突きつけ、
後のZero Trust設計へと議論が進む起点になった。

# Google が到達した Zero Trust

Cloudの普及により、境界の内外という前提が崩れ、
VPNを中心とした境界モデルの費用対効果は急速に悪化した。
この問題に最も早く、かつ現実的に直面した企業の一つがGoogleである。

Googleは、巨大組織の分散化とCloud前提のインフラを背景に、
「特権的イントラネット」を前提とする設計がもはや成立しない状況に置かれた。
さらに、内部侵害が現実のものとなり、
境界が破られることを前提に設計せざるを得なくなる。

この経験からGoogleが到達した結論は明確だった。
場所やネットワークの内外を信頼の根拠にしない。
アクセスは常に、ユーザーと端末の識別、
その時点の状態、対象となる資源に基づいて判断する。

これが後にBeyondCorpとして公開される、
Google流のZero Trust設計である。
ここで重要なのは、Zero Trustが新しいセキュリティ製品ではなく、
Cloud時代において採算が合わなくなった境界信頼を捨てる、
設計上の帰結である点だ。

GoogleはVPNを置き換えたのではない。
VPNが暗黙に担っていた「信頼」を分解し、
認証・認可・暗号化・可視化へと再配置した。
その結果として、「特権的イントラネット」は不要になった。

# Zero Trust 移行

Zero Trustへの移行は、VPNや既存ネットワーク機器を
新しい製品に置き換えることではない。
また「VPNをやめる」こと自体が目的でもない。

従来のVPN前提の運用では、
到達性・場所・ネットワーク境界がまとめて「信頼」として扱われ、
一度境界を越えれば、内側の通信は相対的に許容されてきた。
この曖昧な信頼は、長年の運用を通じて暗黙の前提として固定化している。

Zero Trust移行とは、この暗黙の信頼を分解し、
誰が、どの端末で、どの資源に、どの条件でアクセスしているのかを
明示的なポリシーとして再定義するプロセスである。
ここで得られるうまみは、内／外という場所のラベルを捨てた瞬間に、
「何を信頼しているのか」が構造として露出し、
信頼を最小単位で配置し直せる点にある。

この作業が難しい理由は、技術の高度さにあるのではない。
VPNが覆い隠してきた曖昧な現実を、
否応なく表に出してしまう点にある。
ただし同じ理由で、いったん明示できれば、
そのまま境界依存ではない防御の土台になる。

移行の初期段階で最初に行われるのは制御ではなく可視化である。
既存の通信を壊さずに観測することで、
誰が、どこに、どのように接続しているのかが事実として露出する。

この可視化によって、
目的や責任者が説明できない通信、
端末状態が不明なアクセス、
長年「とりあえず通っていた」通信が、
非準拠トラフィックとして列挙される。
この列挙は単なる棚卸しではなく、
攻撃者が横に動ける経路を一つずつ可視化し、
潰せる形に変換する作業でもある。

Zero Trust移行とは、
新しい仕組みを導入することではなく、
これまで説明不要だった通信を、
一つずつ説明可能な仕様へ引き上げていく過程である。
そして「説明可能になった通信」は、そのまま
最小権限・監査・段階的な遮断へ接続できる。

# どこで詰まるか

Zero Trust移行が詰まるのは、技術が未成熟だからではない。
VPNという境界が、長年にわたって覆い隠してきた曖昧さを、
設計として回収しなければならなくなる点で詰まる。

VPN前提の運用では、多くの通信が
「内側だから」「業務で使っているから」という理由だけで通ってきた。
その結果、誰が何の目的で利用しているのか、
どの条件まで許容されるべきかが、
設計ではなく既成事実として積み重なっている。

Zero Trustでは、この曖昧さを境界に押し戻すことができない。
主体・端末・対象資源・条件を言葉にできない通信は、
制御以前に「意味づけが終わっていないもの」として露出する。

ここで発生する作業は、ツール導入やポリシー記述ではない。
実際の通信を観測し、
それがどの業務のどの工程に紐づいているのかを突き合わせ、
「なぜ必要なのか」を一つずつ言語化する工程である。

重要なのは、この工程が一時的な移行作業ではない点だ。
業務は変化し、システムは増減し、
新しい通信は継続的に発生する。
VPNが境界で肩代わりしていた説明責任は、
Zero Trustではその都度、設計として引き受け直す必要がある。

そのためZero Trust移行は、
完成して終わるプロジェクトにはなり得ない。
境界に依存せず運用を維持するための、
継続的な観測・意味づけ・調整を含む運用そのものになる。

この段階で詰まるのは、
技術や製品の不足ではなく、
この説明責任を誰が、どこまで、引き受けるのかが
組織内で定義されていないことである。

ここに初めて、
現場に入り込み、実通信と業務文脈を結びつけながら
設計を前に進める役割が必要になる。
FDE（Forward Deployed Engineer）というロールは、
この構造的な詰まりを解消するために最適である。
