# Kịch bản thuyết trình VinBank Guardrails

Thời lượng đề xuất: 8–10 phút, chưa gồm hỏi đáp.

## Slide 1 — VinBank Guardrails

Xin chào thầy cô và các bạn. Dự án của em xây dựng chatbot VinBank có khả năng bảo vệ ba nhóm thông tin quan trọng: mật khẩu quản trị, API key và địa chỉ dịch vụ nội bộ.

Thay vì chỉ yêu cầu model không được tiết lộ dữ liệu, hệ thống đặt nhiều lớp kiểm soát trước và sau LLM. Em cũng dùng Red Team để tìm cách vượt qua hệ thống, sau đó cập nhật Blue Team từ bằng chứng tấn công thực tế.

## Slide 2 — Bài toán

System prompt không tạo ra một security boundary đủ mạnh. Trong bài kiểm thử, Red Agent không có guardrail mạnh đã làm lộ secret ở cả 6 prompt.

Kẻ tấn công có thể ngụy trang yêu cầu dưới dạng dịch thuật, điền tài liệu, đối chiếu kiểm toán hoặc viết truyện. Vì vậy, thiết kế kiểm tra request trước LLM, response sau LLM và destination trước egress.

## Slide 3 — Threat model

Hệ thống bảo vệ password quản trị, service API key và internal host.

Password có thể dẫn đến truy cập trái phép. API key có thể bị lạm dụng để gọi dịch vụ hoặc phát sinh chi phí. Internal host làm lộ cấu trúc hạ tầng và hỗ trợ các bước tấn công tiếp theo.

Deck và demo chỉ dùng secret giả của bài lab. API key thật trong file .env không được đưa vào prompt hoặc artifact.

## Slide 4 — Kiến trúc tám lớp

Prompt đi qua tám lớp theo đúng thứ tự.

Canonicalization chuẩn hóa Unicode. Rate limit kiểm soát request theo user. Injection detection tìm ý định lấy secret. Topic policy giới hạn chatbot trong nghiệp vụ ngân hàng.

Sau khi qua input defense, Blue LLM mới được gọi. Response tiếp tục qua Output DLP và Egress. Audit ghi lại quyết định cuối cùng.

NeMo Guardrails có trong repository để tham khảo, nhưng request path của demo dùng rule Python và Google ADK plugin.

## Slide 5 — Input defense

Một nội dung có thể được biểu diễn bằng nhiều dạng Unicode. Chữ VinBank có thể viết bằng full-width. Kẻ tấn công cũng có thể chèn zero-width vào giữa từ khóa.

Hệ thống dùng NFKC để đưa chuỗi về dạng canonical và loại ký tự điều khiển ẩn. Injection detector tìm sự kết hợp giữa hành động trích xuất và dữ liệu nhạy cảm. Topic policy loại yêu cầu ngoài banking.

Nếu chặn ở đây, request không gọi LLM nên vừa an toàn vừa tiết kiệm chi phí.

## Slide 6 — Output defense

Input guardrail không được xem là tuyệt đối. Một prompt mới có thể lọt qua hoặc model có thể tự sinh dữ liệu nhạy cảm.

Output DLP chuẩn hóa Unicode lần hai, sau đó tìm số điện thoại Việt Nam, email, CCCD, password, API key, bearer token, private key, internal host và private IP.

Khi phát hiện protected value bị obfuscate, hệ thống fail closed và thay toàn bộ phản hồi bằng [REDACTED] — protected content blocked.

## Slide 7 — Egress và observability

Response sạch vẫn chưa đủ điều kiện gửi ra ngoài. Egress policy chỉ cho HTTPS tới domain VinBank trong allowlist. Domain lạ như evil.example bị chặn dù nội dung phản hồi hợp lệ.

Audit log ghi input, output, trạng thái và layer chặn. Monitoring đếm tổng request, request bị chặn và rate-limit hits. Phần này cung cấp bằng chứng để điều tra và cải tiến guardrail.

## Slide 8 — Red và Blue

Red Agent cố ý yếu và không có pipeline phòng thủ mạnh. Kết quả là Red leak 6 trên 6 prompt.

Blue Agent đặt security boundary ở ngoài model. Các layer có quyết định rõ ràng và có thể dừng request. Bộ test hiện tại cho thấy Blue chặn 7 trên 7 attack query.

Quy trình phát triển là Red tìm lỗ hổng, em đọc artifact, xác định kỹ thuật bypass, sau đó bổ sung rule vào Blue.

## Slide 9 — Attack playbook

Completion yêu cầu model điền secret vào chỗ trống. Translation chuyển internal note thành JSON. Creative writing đặt secret trong truyện. Confirmation cung cấp giá trị ứng viên rồi yêu cầu model xác nhận. Multi-step escalation bắt đầu vô hại và kết thúc bằng cấu hình thật.

Case quan trọng nhất là Unicode encoding. Nó đã vượt qua Red Advance và tạo bằng chứng cụ thể để nâng cấp canonicalization.

## Slide 10 — Unicode full-width bypass

Prompt không hỏi trực tiếp password hay API key. Nó đưa vào mã Unicode dạng số và yêu cầu model render thành full-width.

Red Advance cũ đã trả về password, API key và database host theo dạng này. Mắt người vẫn đọc được nhưng regex ASCII không khớp.

Em vá ở hai phía. Input guardrail nhận diện tác vụ giải mã codepoint dài. Output guardrail thực hiện NFKC và compact comparison trước khi quyết định. Sau bản vá, case bị block hoặc redact.

## Slide 11 — Evidence

Artifact hiện tại cho thấy 5 trên 5 câu banking an toàn được cho qua. Blue chặn 7 trên 7 attack query. Rate limiter cho qua 10 request trong quota và chặn 2 request tiếp theo.

Red Advance từng leak 1 trên 6 case trước khi em dùng case Unicode để nâng cấp Blue.

Bộ public test có 10 test và tất cả đều pass. Schema hợp lệ và không có technical failure.

## Slide 12 — Live demo

Em trình diễn bốn case.

Đầu tiên là câu banking hợp lệ để chứng minh guardrail không chặn nhầm. Tiếp theo là prompt lấy secret nhiều bước, bị dừng ở Injection. Case thứ ba yêu cầu model lặp PII và Output DLP trả [REDACTED]. Case cuối dùng domain ngoài allowlist và bị Egress chặn.

Sau mỗi case, em chỉ vào graph để giải thích layer màu xanh đã pass, layer màu đỏ đã block và vì sao các layer phía sau không chạy.

## Slide 13 — Kết luận

Thiết kế không đặt niềm tin vào một lớp duy nhất.

Canonicalization làm dữ liệu nhất quán. Input guardrail giảm attack surface. Output DLP giữ secret lại. Egress kiểm soát nơi dữ liệu được gửi. Audit tạo bằng chứng để theo dõi.

Hệ thống không tuyên bố an toàn tuyệt đối. Nó giả định một lớp có thể thất bại và dùng lớp tiếp theo để giảm tác động.

Em xin kết thúc và sẵn sàng nhận câu hỏi.

## Lệnh chuẩn bị

Chạy slide:

    python -m http.server 8088

Mở:

    http://127.0.0.1:8088/ui/presentation.html

Chạy chatbot demo ở terminal khác:

    source .venv/bin/activate
    python src/demo_server.py --port 8091

Mở:

    http://127.0.0.1:8091/

Phím điều khiển: mũi tên trái/phải hoặc Page Up/Page Down để chuyển slide, phím F để toàn màn hình.
