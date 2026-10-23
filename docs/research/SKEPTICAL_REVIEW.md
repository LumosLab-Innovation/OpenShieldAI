# OpenShieldAI — phản biện hiệu quả và cổng chấp nhận

Ngày nghiên cứu: **2026-10-24**. Trạng thái: **research / design proposal**; chưa có runtime, kết quả benchmark hay năng lực bảo vệ production được xác nhận trong review này.

Vai trò tài liệu này là bác bỏ tính năng không chứng minh được giá trị, kể cả khi tên gọi hấp dẫn hoặc có paper tương tự. Đây không phải phê duyệt triển khai. Rubric dưới đây là chính sách đề xuất cho OpenShieldAI, không phải ngưỡng an toàn được NIST hoặc paper chứng nhận.

## 1. Luận điểm cần giữ và tuyên bố phải bỏ

Tầm nhìn có ý nghĩa: giúp đội vận hành phòng ngừa, phát hiện, ứng phó và phục hồi trước các cuộc tấn công có tốc độ, quy mô và mức tự động hóa ngày càng cao. Hiệu quả phải đo bằng thiệt hại tránh được, chất lượng quyết định và thời gian con người tiết kiệm được trong phạm vi cụ thể.

Không cần xác định một kẻ tấn công có dùng AI hay không mới phòng thủ được. Hành vi xâm nhập, quyền bị lạm dụng, thay đổi dữ liệu và khả năng gián đoạn dịch vụ mới là đối tượng phải đo. Nhãn “AI attack detector” không tự tạo ra tín hiệu đáng tin.

Không được dùng các câu sau như năng lực hiện hữu:

- “Tiên phong thế giới”, “chống mọi AI attack”, “zero false positive”, “tự bảo vệ mọi hệ thống”.
- “Thay thế SOC / EDR / SIEM / đội incident response / hệ thống backup”.
- “AI tự khôi phục dữ liệu đã mất” hoặc “hoàn tác rò rỉ dữ liệu”.
- “Đã an toàn” chỉ vì agent chạy xong, model tự tin hoặc không thấy alert.
- “Production ready” chỉ vì unit test, demo hoặc benchmark mô phỏng đạt điểm cao.

Các câu về tầm nhìn phải dùng dạng mục tiêu nghiên cứu hoặc định hướng dài hạn. Mọi claim hiệu năng cần gắn phiên bản, môi trường, dữ liệu, baseline, mẫu thử và giới hạn.

## 2. Rubric nhận một feature vào kế hoạch

Mỗi đề xuất phải trả lời đủ các câu hỏi áp dụng. Trạng thái chỉ gồm `pass`, `fail`, `unknown`, `not_applicable_with_reason`; không cộng điểm để bù cho một cổng bảo mật bị fail.

| Cổng | Bằng chứng cần có | Loại nếu thiếu |
| --- | --- | --- |
| G1. Có vấn đề thật | Một failure mode, người chịu trách nhiệm, tài sản, hậu quả và công việc hiện nay phải làm | Feature chỉ vì có thể gọi LLM |
| G2. Có quan sát được | Data source, schema, timestamp, freshness, retention, quyền truy cập và phần không quan sát được | Suy luận rằng không có alert nghĩa là không bị xâm nhập |
| G3. Có baseline | Runbook/rule hiện có, công cụ OSS tương đương và workflow analyst cùng dữ liệu/quyền/budget | So với “không làm gì” hoặc chatbot yếu được dựng để thua |
| G4. Có ground truth | Dữ liệu holdout, expected facts/actions được niêm phong, benign controls và verifier độc lập | Model vừa đề xuất vừa chấm kết quả của chính nó |
| G5. Có ích đo được | Metric chính, mức suy giảm chấp nhận được, cỡ mẫu và chi phí được định trước | Chỉ đếm số alert, số agent, token hoặc độ dài report |
| G6. Có giới hạn hành động | Scope, precondition, quyền tối thiểu, approval, idempotency, timeout, budget, postcheck | Free-form shell/API có quyền cao do model trực tiếp điều khiển |
| G7. Có đường thất bại | Missing/stale/tainted telemetry, provider lỗi, rate limit, retry, cancellation, partial result, escalation | Tự ghi success hoặc âm thầm bỏ incident |
| G8. Có đường vận hành | Owner, nguồn gốc upstream, license, version pin, migration/rollback và cập nhật playbook có review | Tích hợp repo chỉ vì nổi tiếng, không ai vận hành hoặc kiểm thử |

`unknown` nghĩa là chưa được phép quảng bá hoặc phát hành năng lực đó. Một tính năng chỉ nhập dữ liệu và đề xuất có thể được thử nghiệm trước feature thực thi; không được mô tả thử nghiệm đó như đã hoàn thiện response.

## 3. Decision matrix ban đầu

| Ý tưởng | Phán quyết | Điều kiện để đổi phán quyết |
| --- | --- | --- |
| Evidence-backed incident timeline và danh sách câu hỏi cần điều tra | Nhận vào thử nghiệm | Mỗi sự kiện có evidence ID, timestamp, nguồn; phân biệt observation / hypothesis / unknown; đo cả sai sót và thời gian review |
| Triage một nhóm incident có telemetry rõ | Nhận có điều kiện | Chọn nhóm theo data access thực tế; có benign controls, holdout và cơ chế abstain/escalate |
| Playbook theo tình huống, gắn ATT&CK / D3FEND | Nhận có điều kiện | Mapping là tham chiếu; phải có precondition và phép thử của control trên hệ thống cụ thể |
| Đề xuất containment có scope, tác động và kế hoạch xác minh | Nhận vào thử nghiệm | Con người duyệt; thiếu quyền hoặc bằng chứng phải được ghi rõ; không biến recommendation thành kết quả đã thực hiện |
| Kiểm tra khả năng phục hồi và diễn tập restore | Có giá trị | Có backup thật, mốc phục hồi, quyền restore tách biệt, môi trường cô lập, kiểm tra integrity/application và đo RPO/RTO |
| Detection engineering bằng AI | Chỉ thử nghiệm | Rule phải compile, chạy trên malicious + benign replay, kiểm tra field mapping, query cost và cảnh báo false positive; deploy cần review |
| Multi-agent SOC | Chưa nhận mặc định | Thắng single-agent và deterministic workflow cùng dữ liệu, quyền, cost/time; không tăng unsafe action hoặc làm audit khó hơn |
| Auto block IP / isolate host / disable account | Hoãn production | Có adapter định kiểu, action catalog, blast-radius cap, approval theo rủi ro, canary, postcheck và phương án khôi phục phù hợp |
| Auto patch / self-healing | Hoãn | Có source/config context, repro, regression test, deploy owner, canary/rollback; giảm được incident mà không phá availability |
| AI đọc report rồi viết lại thành một report khác | Bác bỏ như giá trị cốt lõi | Phải chứng minh giảm việc analyst hoặc cải thiện quyết định; có thể là UI phụ trợ |
| AI phát hiện mọi zero-day từ mọi log | Bác bỏ claim | Có thể nghiên cứu một hypothesis/scenario cụ thể, không chuyển thành cam kết toàn cục |
| AI khôi phục ransomware không cần backup hoặc decryptor hợp lệ | Bác bỏ | Không có cơ sở kỹ thuật tổng quát; chỉ hỗ trợ assessment, provenance và workflow phục hồi hợp lệ |
| Tự xóa log/malware, rebuild hoặc restore đè hệ thống đang bị tấn công | Bác bỏ mặc định | Owner chỉ đạo qua runbook đã kiểm thử, bảo toàn chứng cứ và chấp nhận nguy cơ mất dữ liệu; một số hành động không thể rollback |
| Phát hiện “AI-generated attacker” làm feature chính | Bác bỏ | Chỉ xem xét nếu có dấu hiệu đo được và cải thiện quyết định hơn phát hiện hành vi thông thường |
| Kết nối OpenHunterAI đầu tiên để tạo roadmap | Sai thứ tự | Shield phải chứng minh một defense workflow độc lập trước; Hunter là nguồn evidence bổ sung sau đó |

## 4. Cách thử để không tự đánh lừa mình

### Baseline và ablation

Chạy ít nhất các nhánh áp dụng trên cùng tập case, cùng tool permissions và cùng giới hạn thời gian:

1. Rule/runbook deterministic và công cụ hiện có.
2. Analyst dùng workflow hiện có; ghi cả thời gian chờ và review khi so trải nghiệm người dùng.
3. Một model với workflow đơn giản, làm baseline cho mọi đề xuất nhiều agent hoặc reasoning phức tạp.
4. OpenShieldAI và các nhánh tắt LLM, tắt retrieval, tắt từng agent quan trọng để xác định thành phần nào có ích.

Không bắt buộc xây mọi baseline bằng code mới. Dùng công cụ sẵn có và ghi rõ biến nào được giữ cố định. Nếu hệ thống phức tạp không hơn nhánh đơn giản trong metric đã định trước, bỏ phần phức tạp hoặc hạ xuống research-only.

### Dữ liệu và chống leakage

- Tách theo campaign / thời gian / môi trường, không chỉ random từng log row; cùng một campaign rơi vào train và test sẽ làm điểm đẹp giả.
- Holdout không đưa đáp án, labels, expected commands hoặc thông tin grader vào agent environment.
- Có hoạt động quản trị hợp lệ giống hành vi tấn công, case không có attack, missing log, clock skew, duplicate/out-of-order event và bằng chứng mâu thuẫn.
- Có attacker-controlled text trong log, file name, email, ticket và tool output để thử prompt injection; bộ lọc prompt không được coi là ranh giới quyền hạn.
- Dùng expected outcomes và deterministic checks khi có thể; LLM judge chỉ hỗ trợ chấm diễn giải, không là chứng cứ duy nhất của safety hoặc containment thành công.
- Ghi số lần chạy, variation, seed nếu có, model/provider/version, rule/adapter version, chi phí, thời gian và confidence intervals phù hợp. Không chỉ chọn lần tốt nhất.

### Metrics bắt buộc theo output

| Output | Đo gì | Cách dễ tạo điểm giả cần chặn |
| --- | --- | --- |
| Triage/detection | Incident-level precision/recall, recall theo scenario/severity, false alerts trên đơn vị thời gian/khối lượng, abstention và backlog | Accuracy cao trên dữ liệu gần như toàn benign; gộp mọi scenario để che nhóm fail |
| Timeline/analysis | Fact precision, evidence attribution, missing critical facts, unsupported conclusions và analyst review time | Chỉ chấm độ trôi chảy, số facts đúng nhưng không phạt hallucination |
| Containment proposal | Lựa chọn đúng mục tiêu, giảm phạm vi xâm nhập dự kiến, unsafe proposal rate và review burden | Chỉ kiểm tra JSON hợp lệ hoặc có action trong danh sách |
| Action execution | Independent postcheck, idempotency, blast radius, service availability, rollback success nếu áp dụng | Tool exit code 0 hoặc API accepted bị coi là đã containment |
| Recovery | Restore integrity, application consistency, RPO/RTO, backup provenance và quyền truy cập sau restore | File tồn tại hoặc process chạy bị coi là dữ liệu sạch và an toàn |
| Agent security | Unauthorized effects thực tế, secret exposure, scope escape, task utility trong attack/benign runs | Chỉ chấm classifier có “nhận ra injection” mà không kiểm tra hành động |
| Economics | Cost/incident, analyst minutes, p50/p95 latency, queue throughput và timeout rate | Chỉ so chi phí model; bỏ công vận hành, context retrieval và review |

Phải báo abstention trong mẫu số của coverage và workload. Hệ thống từ chối mọi case có thể ít hành động sai nhưng không có năng lực phòng thủ hữu ích. Không dùng AUROC hoặc accuracy một mình cho bài toán hiếm attack; công bố base rate và precision/recall tại operating point thực tế.

Ngưỡng phát hành phải được chốt theo từng scenario trước khi mở holdout. Không có một ngưỡng precision/recall duy nhất đủ an toàn cho cả việc gợi ý điều tra và việc ngắt mạng một hệ thống sống còn. “Không thấy unsafe action trong N lần thử” là kết quả hữu hạn, không phải bằng chứng rủi ro bằng 0.

## 5. Release blockers không được đánh đổi bằng deadline

Các lỗi dưới đây chặn release của năng lực liên quan, không thể miễn bằng model confidence:

- Không có explicit authorization, asset/tenant scope, role hoặc incident ownership phù hợp.
- Untrusted evidence có thể thay đổi policy, approval, tool permissions hoặc lấy được credential.
- Một approval không ràng buộc chính xác action, target, parameters, policy/plan version, approver và expiry; approval dùng lại được sau khi plan thay đổi.
- Executor nhận free-form command/URL từ LLM mà không kiểm tra scope, parameters và điều kiện hiện tại ngay trước thực thi.
- Không phân biệt `proposed`, `approved`, `attempted`, `verified`, `failed`, `partially_verified`, `unknown`; lỗi tool/thiếu dữ liệu biến thành verified.
- Raw secrets/credential/PII nhạy cảm ra prompt, log, report hoặc adapter có quyền thừa; thiếu retention/redaction phù hợp.
- Chỉ có agent tự xác minh thành công, không có independent observation hoặc postcondition đáng tin.
- Không biết tác động availability, phụ thuộc hệ thống hay đường khôi phục cho action production có rủi ro.
- Retry có thể block/rotate/delete/restore lặp lại ngoài ý muốn; action đang chạy không thể cancel hoặc giới hạn thời gian/phạm vi.
- Evidence bị sửa/xóa để “dọn sạch”; không giữ được provenance, checksum, timestamp và audit trail cần thiết.
- Restore được mô tả như eradication: dữ liệu đã phục hồi không chứng minh persistence, credential theft hoặc initial access đã xử lý.
- Backup chưa restore-test nhưng được báo recoverable; thiếu backup nhưng vẫn hứa lấy lại dữ liệu.
- Một fixture/demo/mock được đưa vào production path hoặc quảng bá như kết quả thực tế.

Kill switch phải chặn hành động mới và thu hồi authority; nó không được hứa hoàn tác được hành động đã xảy ra. Fail mode cần định theo action: tự mở firewall lại khi TTL hết cũng có thể nguy hiểm; giữ block vô hạn cũng có thể làm dịch vụ chết. Chính sách recovery/escalation phải được duyệt rõ.

## 6. Minimum valuable slice đáng thử

**Một nhóm incident, một nguồn telemetry thật có quyền đọc, một workflow điều tra có thể replay.** Chọn nhóm incident sau khi xác nhận lấy được dữ liệu, không bắt đầu từ danh sách hàng chục integration.

Ví dụ phù hợp để tuyển pilot: dấu hiệu tài khoản bị chiếm trong một web/service platform, có identity/application audit logs và một owner có thể đánh giá ground truth. Đây là ứng viên thử nghiệm, không phải cam kết đã có connector hay khả năng bao phủ.

Vòng hoàn chỉnh đầu tiên:

1. Nhận sanitized evidence bundle có schema/version, timestamps và provenance.
2. Dựng timeline, phân biệt điều quan sát được và giả thuyết; phát hiện dữ liệu thiếu.
3. Đề xuất các bước điều tra và containment từ playbook đã review, ghi preconditions và tác động.
4. Analyst duyệt hoặc từ chối, chỉnh quyết định và ghi lý do; chưa cần quyền production write.
5. Replay cùng case, so với baseline về chất lượng quyết định và tổng thời gian analyst.
6. Chỉ sau khi thắng baseline mới chọn một action adapter hẹp, kiểm thử trong lab và shadow mode trước production.

Recovery-readiness là hướng thử song song có giá trị nếu có backup owner và môi trường restore riêng. Đầu ra là bằng chứng restore và hạn chế; không phải lời hứa “chống mất dữ liệu”.

Sản phẩm chỉ đáng tiếp tục mở rộng nếu giảm công việc thật mà không làm giảm khả năng phát hiện/ra quyết định hoặc tăng rủi ro. Nếu chưa đủ mẫu để kết luận, ghi `inconclusive`; không sửa metric sau khi xem điểm để biến thành thành công.

## 7. Rigor cho nguồn nghiên cứu và upstream

### Nguồn đã đọc và kết luận được phép rút ra

| Nguồn chính | Quan sát từ nguồn | Giới hạn áp dụng |
| --- | --- | --- |
| [NIST SP 800-61r3 announcement](https://www.nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations), 2025-04-03; [publication](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | Incident response thuộc quản trị rủi ro xuyên suốt tổ chức, gắn CSF 2.0 | Framework không chứng nhận hiệu năng một agent |
| [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide) | Cần backup offline/encrypted, kiểm thử restore, cô lập có phối hợp và bảo toàn evidence | Hướng dẫn vận hành, không phải benchmark AI; phiên đọc này truy cập được kết quả chỉ mục nhưng HTML trực tiếp trả 403 |
| [MITRE D3FEND](https://d3fend.mitre.org/) | Knowledge graph cho countermeasures, hữu ích làm vocabulary/mapping | Mapping không chứng minh control có mặt, hoạt động hay chặn được campaign cụ thể |
| [CyberSOCEval paper](https://arxiv.org/abs/2509.20166), v2 2025-11-10; [official code suite](https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks) | Đánh giá malware analysis và threat-intelligence reasoning; reasoning scaling không mặc nhiên cho lợi ích như coding/math | Không phải end-to-end SOC hoặc production response evaluation |
| [Large Language Models are Autonomous Cyber Defenders](https://arxiv.org/abs/2505.04843), v2 2025-07-19 | Nghiên cứu multi-agent ACD trong CybORG CAGE 4 | Bằng chứng mô phỏng, không thể suy ra enterprise autonomy |
| [Cyber Defense Benchmark](https://arxiv.org/abs/2604.19533v3), v3 2026-04-23; [versioned PDF](https://arxiv.org/pdf/2604.19533v3) | Benchmark-discovery lead cho Windows-log hunting; reviewer xác nhận abstract và PDF trình bày khác nhau về kết quả và model coverage | Không nhận exact performance figures làm bằng chứng định lượng trước khi artifact được đối chiếu; không dùng để kết luận mọi AI defense đều thất bại |
| [AgentDojo paper](https://arxiv.org/abs/2406.13352); [official repository](https://github.com/ethz-spylab/agentdojo) | External tool data có thể mang prompt injection; benchmark gồm tasks và attack cases để đo utility lẫn security | Dataset công khai không đại diện toàn bộ payload mới; cần adaptive và domain-specific tests |
| [Microsoft Copilot for Security RCT](https://www.microsoft.com/content/dam/microsoft/final/en-us/microsoft-product-and-services/microsoft-dynamics-365/pdf/Microsoft-Copilot-for-Security-productivity-findings-Whitepaper-Jan2024.pdf), 2024-01 | Controlled study có lợi ích theo task; phần chấm summary không chấm unsupported claims; response task có thể chậm hơn | Vendor study với sample scenarios, không phải hiệu quả ngăn chặn breach thực tế |
| [Microsoft Phishing Triage Agent RCT](https://cdn-dynmedia-1.microsoft.com/is/content/microsoftcorp/microsoft/bade/documents/products-and-services/en-us/security/randomized-controlled-trial-for-phishing-triage-agent-accessible.pdf), 2025-10 | Nghiên cứu task hẹp; phần lớn throughput gain được gắn với ưu tiên queue, hơn là lời giải thích | Vendor study với corpus 93 email và lỗi tổng hợp để khảo sát hành vi; không lấy headline làm kỳ vọng OpenShieldAI |

Không paper nào ở đây xác nhận OpenShieldAI có hiệu năng tương đương. Cơ hội hợp lý rút ra từ tập nguồn là thiết kế workflow hẹp, evidence rõ, queue/prioritization tốt và đo con người + hệ thống; không phải cho thêm agent rồi coi là tự chủ.

### Điều kiện trước khi gọi một repo là “integrated”

- Xác minh repo chính chủ, phiên bản/commit bất biến, license của code **và** rule/data/model đi kèm, tình trạng maintenance và security advisories.
- Ghi rõ `reference_only`, `candidate`, `adapter_planned`, `lab_validated` hoặc `production_validated`; một link trong README không phải integration.
- Chọn dùng qua adapter hoặc giao thức có contract; tránh vendor toàn bộ repo nếu chỉ cần một capability nhỏ.
- Có test contract, failure modes, scope enforcement, data handling và owner cập nhật. Không tự động kéo playbook/rule/model rồi chạy production.
- Paper/repo tự công bố điểm phải được mô tả là kết quả tác giả báo cáo cho đúng task; reproduce local riêng trước mọi claim của dự án.

## 8. Kết luận phản biện hiện tại

**Giữ tầm nhìn, nhận hướng research và nền tảng policy/evaluation; chưa phê duyệt capability production nào.** Một nền tảng gắn telemetry đáng tin, incident workflow, policy-gated action và independent verification có giá trị tiềm năng. Một bộ agent nói chuyện về report thì không đủ.

OpenHunterAI nên được ghép sau bằng contract evidence/finding đã sanitize và provenance rõ. Finding của Hunter không tự chứng minh có incident đang diễn ra; “fix đã deploy” không tự chứng minh eradication; retest bên ngoài không tự chứng minh recovery bên trong.

Chưa chạy benchmark, thực nghiệm operator, connector hay restore drill. Rủi ro còn lại: hiệu quả, chi phí, telemetry availability và độ an toàn của action chưa có bằng chứng riêng cho OpenShieldAI.

## 9. Disposition sau khi đọc thiết kế cụ thể

Review ngày 2026-10-24 đối chiếu `AGENTS.md`, `CONTEXT.md`, PRD, architecture, guardrails, contracts, acceptance criteria, evaluation, worker/LLM specifications, production readiness, roadmap, threat model, Hunter collaboration và research/playbooks hiện có. Đây là review hồ sơ S0, không phải audit một implementation.

**Kết luận cuối cho hồ sơ S0: không còn critical blocker về thiết kế/tuyên bố năng lực trong scope tài liệu đã review; chấp nhận làm đầu vào cho implementation S1. Chưa chấp nhận một capability runtime hoặc production nào.** README, license/community policy và documentation checks đã được review; cấu hình GitHub cần được maintainer xác minh riêng. Không được đổi kết luận này thành “security approved” hoặc “đã chứng minh hiệu quả”.

| Vấn đề phản biện | Thiết kế hiện xử lý thế nào | Disposition |
| --- | --- | --- |
| AI wrapper hoặc report-to-chat là toàn bộ sản phẩm | PRD yêu cầu workflow no-LLM; EVALUATION so deterministic/current-tool/operator và phần tăng thêm của AI | Đủ cơ sở thử nghiệm; tiếp tục hay bỏ AI phụ thuộc kết quả |
| Thiếu telemetry và authority | S1 local replay; S2 mới chọn actual source/pilot; enrollment tách riêng với báo cáo/alert | Chấp nhận sequencing; chưa có telemetry support thực tế |
| Autonomous action gây hại | Model không có executor route; R2 per-action approval; R3 human-run, two-person review; typed adapter S3 | Đủ yêu cầu thiết kế; tests/implementation đều chưa pass |
| Tự xác nhận containment | Receipt, verification và closure tách biệt; observer kiểm tra hiệu ứng và service health | Chấp nhận yêu cầu; observer thực tế phải được đánh giá theo môi trường |
| Recovery bị quảng cáo quá mức | Restore isolated, pinned snapshot/key, integrity/application/contamination checks, measured RPO/RTO; không undo exfiltration | Chấp nhận giới hạn; chưa có bằng chứng một restore thành công |
| Benchmark bị contamination hoặc không đo ích lợi | Ground truth độc lập detector; incident-level holdout; benign/missing/adversarial variants; target đăng ký trước pilot | Đủ thiết kế thử nghiệm; 40 case khởi đầu không chứng minh broad efficacy |
| All-refusal hoặc đẹp report bị coi là thành công | Evaluation giữ unknown/missed cases, active review time và false negatives; inconclusive phải ở shadow | Chấp nhận; phải công bố actual confusion matrix và analyst workload |
| Phòng ngừa chưa chứng minh được | Research nêu WAF/control candidates; PRD giới hạn recommendation; acceptance/roadmap yêu cầu attack/benign replay, independently blocked effect và service SLO | Chấp nhận cổng đề xuất; chưa được claim prevention efficacy |
| Hunter làm trung tâm hoặc cấp quyền chéo | S5 sau standalone gates; manual file exchange, enrolled-asset mapping, không thừa hưởng authority | Chấp nhận contract proposal; chưa có integration |

### Các điều kiện còn lại trước khi nâng claim

- **Prevention:** mỗi control phải có threat hypothesis, attack replay, benign traffic và independent blocked-effect verification; báo false blocking, availability/latency và scope. Installed rule, mapping D3FEND hoặc giảm số alert không đủ chứng minh ngăn tấn công.
- **Utility:** target giảm 20% median active triage time trong EVALUATION là giả thuyết nội bộ, chưa được chứng minh. Không tăng false negatives cần được xem cùng uncertainty và sample size; không đủ dữ liệu thì chưa qua gate.
- **Real operations:** pilot owner, incident commander, telemetry coverage, quyền, dependency graph và recovery objectives vẫn chưa chọn. Đây là lý do chưa có quyền production, không phải lý do để giả lập support.
- **Scaling:** single Linux service/SQLite pilot không chứng minh enterprise tenancy, throughput, HA hay khả năng phối hợp khủng hoảng ở nhiều hệ thống.
- **Research consistency:** tài liệu nghiên cứu không tự cấp standing authorization hoặc mở rộng incident families. Nếu nghiên cứu đề xuất autonomy khác guardrails hiện hành, phải qua ADR/owner decision và acceptance mới trước khi implement.

### Final checks và sửa sai trong review

- Đọc thêm README, security/contributing/conduct/licensing, documentation map, ADR và manual-enrichment policy. README phân biệt rõ mục tiêu phòng ngừa/ứng phó/phục hồi với danh sách feature chưa hỗ trợ, no-runtime stage, upstream candidates và license source-available.
- `python scripts/check_docs.py`: **28 Markdown files, 15 pinned upstream records, 0 errors** tại snapshot review này.
- `python -m unittest discover -s scripts -p "test_*.py"`: **5 tests passed**. Đây là checks cho documentation/provenance, không phải benchmark security.
- Đã bỏ exact Cyber Defense Benchmark figure từng lấy từ abstract sau khi mở versioned PDF và xác nhận source mismatch. Nguồn này chỉ còn là discovery lead, không làm căn cứ định lượng cho thiết kế hoặc marketing.
- Các điểm không nhất quán được nêu trong review về S1/S3 adapter scope, breadth của playbook suite và future standing authorization đã được researcher chuẩn hóa theo S0–S5 và guardrails. Common envelope/typo cũng đã được chỉnh; prevention gate đã có trong acceptance/roadmap.
- Kênh private vulnerability reporting của GitHub cần được maintainer enable/verify trước khi dựa vào nó như kênh báo lỗi. Reviewer chưa kiểm tra remote configuration, metadata hay thao tác publish.

Review không tìm thấy critical S0 blocker đối với việc công bố hồ sơ nghiên cứu hoặc bắt đầu S1 trong scope đã giới hạn. Mọi release blocker ở mục 5 vẫn có hiệu lực và chưa được kiểm thử trên runtime.
