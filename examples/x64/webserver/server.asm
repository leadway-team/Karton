format ELF64 executable
entry start

segment readable writeable
    buffer      rb 5000
    filebuf     rb 8000
    filename    rb 50
    itoa_buf    rb 11

    http_header_html db 'HTTP/1.1 200 OK',13,10,\
                         'Content-Type: text/html',13,10,\
                         'Connection: close',13,10,13,10
    header_len_html = $ - http_header_html

    http_header_ico db 'HTTP/1.1 200 OK',13,10,\
                        'Content-Type: image/x-icon',13,10,\
                        'Connection: close',13,10,13,10
    header_len_ico = $ - http_header_ico

    http_header_css db 'HTTP/1.1 200 OK',13,10,\
                        'Content-Type: text/css',13,10,\
                        'Connection: close',13,10,13,10
    header_len_css = $ - http_header_css

    http_header_woff db 'HTTP/1.1 200 OK',13,10,\
                         'Content-Type: font/woff2',13,10,\
                         'Connection: close',13,10,13,10
    header_len_woff = $ - http_header_woff

    log_index_prefix db 'Sent: index.html at '
    log_index_prefix_len = $ - log_index_prefix

    log_favicon_prefix db 'Sent: favicon.ico at '
    log_favicon_prefix_len = $ - log_favicon_prefix

    log_css_prefix db 'Sent: styles.css at '
    log_css_prefix_len = $ - log_css_prefix

    log_font_prefix db 'Sent: font.woff2 at '
    log_font_prefix_len = $ - log_font_prefix

    log_nl db 10

    sockfd   dq 0
    clientfd dq 0
    filefd   dq 0
    filelen  dq 0

    sockaddr:
        dw 2
        dw 0x991f
        dd 0
        rb 8

segment readable executable
start:
    mov rax, 41
    mov rdi, 2
    mov rsi, 1
    mov rdx, 0
    syscall
    mov [sockfd], rax

    mov rax, 49
    mov rdi, [sockfd]
    lea rsi, [sockaddr]
    mov rdx, 16
    syscall

    mov rax, 50
    mov rdi, [sockfd]
    mov rsi, 10
    syscall

.accept_loop:
    mov rax, 43
    mov rdi, [sockfd]
    xor rsi, rsi
    xor rdx, rdx
    syscall
    mov [clientfd], rax

    mov rax, 0
    mov rdi, [clientfd]
    lea rsi, [buffer]
    mov rdx, 5000
    syscall

    lea rsi, [buffer]
    lea rdi, [css_str]
    mov rcx, 5000
.find_css:
    push rcx
    push rsi
    push rdi
    mov rcx, css_str_len
    repe cmpsb
    pop rdi
    pop rsi
    pop rcx
    je .use_css
    inc rsi
    loop .find_css

    lea rsi, [buffer]
    lea rdi, [favicon_str]
    mov rcx, 5000
.find_favicon:
    push rcx
    push rsi
    push rdi
    mov rcx, favicon_str_len
    repe cmpsb
    pop rdi
    pop rsi
    pop rcx
    je .use_favicon
    inc rsi
    loop .find_favicon

    lea rsi, [buffer]
    lea rdi, [font_str]
    mov rcx, 5000
.find_font:
    push rcx
    push rsi
    push rdi
    mov rcx, font_str_len
    repe cmpsb
    pop rdi
    pop rsi
    pop rcx
    je .use_font
    inc rsi
    loop .find_font

.use_index:
    lea rdi, [filename]
    lea rsi, [index_file]
    mov rcx, index_file_len
    rep movsb
    mov byte [rdi], 0
    jmp .log_index

.use_favicon:
    lea rdi, [filename]
    lea rsi, [favicon_file]
    mov rcx, favicon_file_len
    rep movsb
    mov byte [rdi], 0
    jmp .log_favicon

.use_css:
    lea rdi, [filename]
    lea rsi, [css_file]
    mov rcx, css_file_len
    rep movsb
    mov byte [rdi], 0
    jmp .log_css

.use_font:
    lea rdi, [filename]
    lea rsi, [font_file]
    mov rcx, font_file_len
    rep movsb
    mov byte [rdi], 0
    jmp .log_font

.log_index:
    mov rax, 1
    mov rdi, 1
    lea rsi, [log_index_prefix]
    mov rdx, log_index_prefix_len
    syscall
    jmp .log_time

.log_favicon:
    mov rax, 1
    mov rdi, 1
    lea rsi, [log_favicon_prefix]
    mov rdx, log_favicon_prefix_len
    syscall
    jmp .log_time

.log_css:
    mov rax, 1
    mov rdi, 1
    lea rsi, [log_css_prefix]
    mov rdx, log_css_prefix_len
    syscall
    jmp .log_time

.log_font:
    mov rax, 1
    mov rdi, 1
    lea rsi, [log_font_prefix]
    mov rdx, log_font_prefix_len
    syscall
    jmp .log_time

.log_time:
    mov rax, 201
    xor rdi, rdi
    syscall
    call itoa

    mov rdi, 1
    mov rsi, rax
    mov rdx, itoa_buf + 10
    sub rdx, rsi
    mov rax, 1
    syscall

    mov rax, 1
    mov rdi, 1
    lea rsi, [log_nl]
    mov rdx, 1
    syscall

    jmp .send_file

.send_file:
    mov rax, 2
    lea rdi, [filename]
    xor rsi, rsi
    mov rdx, 0
    syscall
    mov [filefd], rax
    cmp rax, 0
    jl .close_client

    mov rax, 0
    mov rdi, [filefd]
    lea rsi, [filebuf]
    mov rdx, 8000
    syscall
    mov [filelen], rax

    mov rax, 3
    mov rdi, [filefd]
    syscall

    mov rax, 1
    mov rdi, [clientfd]

    lea rsi, [filename]
    lea rdi, [favicon_file]
    mov rcx, favicon_file_len
    cld
    repe cmpsb
    je .write_ico_header

    lea rsi, [filename]
    lea rdi, [css_file]
    mov rcx, css_file_len
    cld
    repe cmpsb
    je .write_css_header

    lea rsi, [filename]
    lea rdi, [font_file]
    mov rcx, font_file_len
    cld
    repe cmpsb
    je .write_woff_header

    lea rsi, [http_header_html]
    mov rdx, header_len_html
    jmp .write_header

.write_ico_header:
    lea rsi, [http_header_ico]
    mov rdx, header_len_ico
    jmp .write_header

.write_css_header:
    lea rsi, [http_header_css]
    mov rdx, header_len_css
    jmp .write_header

.write_woff_header:
    lea rsi, [http_header_woff]
    mov rdx, header_len_woff
    jmp .write_header

.write_header:
    mov rax, 1
    mov rdi, [clientfd]
    syscall

    mov rax, 1
    mov rdi, [clientfd]
    lea rsi, [filebuf]
    mov rdx, [filelen]
    syscall

.close_client:
    mov rax, 3
    mov rdi, [clientfd]
    syscall

    jmp .accept_loop

itoa:
    push rcx
    push rdx
    mov rcx, 10
    lea rdi, [itoa_buf + 10]
    mov byte [rdi], 0
.itoa_loop:
    xor rdx, rdx
    div rcx
    dec rdi
    add dl, '0'
    mov [rdi], dl
    test rax, rax
    jnz .itoa_loop
    mov rax, rdi
    pop rdx
    pop rcx
    ret

segment readable
favicon_str db 'GET /favicon.ico '
favicon_str_len = $ - favicon_str

css_str db 'GET /styles.css '
css_str_len = $ - css_str

font_str db 'GET /font.woff2 '
font_str_len = $ - font_str

favicon_file db 'static/favicon.ico'
favicon_file_len = $ - favicon_file

css_file db 'static/styles.css'
css_file_len = $ - css_file

font_file db 'static/font.woff2'
font_file_len = $ - font_file

index_file db 'index.html'
index_file_len = $ - index_file
