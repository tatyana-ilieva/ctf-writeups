# PicoCTF: buffer overflow 1

## Context

In this challenge, we are given a vulnerable Linux binary (`vuln`) along with its source code (`vuln.c`). The goal is to exploit a stack-based buffer overflow to redirect execution to a hidden function (`win`) that prints the flag. The description given is "control the return address". The program reads user input from standard input and does not perform proper bounds checking, making it vulnerable to memory corruption.

## Background Information: Buffer Overfllows

A buffer overflow occurs when a program writes more data to a memory buffer
than it was allocated to hold. In C programs, this commonly happens when
functions such as `gets`, `scanf`, or `fgets` are used improperly.

By overflowing a buffer on the stack, it is possible to overwrite
adjacent memory such as the saved return address. By overwriting this return address with a chosen value, an attacker can redirect execution to an arbitrary function within the binary.


## Vulnerability

The vulnerability in this challenge is a stack-based buffer overflow.
The program reads user input into a buffer without checking its length,
allowing an attacker to overwrite the saved return address on the stack.

Examining `vuln.c` reveals the core vulnerability:

#define BUFSIZE 32

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

Here, we see that the buffer buf is only 32 bytes long. The function gets() is used to read input, but gets() does not perform any bounds checking and will continue reading until a newline is encountered.

This allows user input to overflow buf and overwrite data stored after it on the stack, including the saved return address.

Also, the program includes a win() function as shown below:

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

The win() function reads the flag from flag.txt and prints it, but it is never called during normal program execution, which also makes it a target for exploitation. 

## Exploitation

Step 1: Identifying the overflow point

To determine how much input is required to overwrite the return address, I sent increasingly long, predictable strings to the program once prompted for input. Supplying more than 32 bytes caused the program to crash with a segmentation fault, confirming that the buffer overflow was reachable.

By continuing to increase the input length and observing crashes, it became clear that data beyond the buffer was overwriting the saved instruction pointer.

Using repeated characters ("A" * N) made it easy to recognize when the return address was being overwritten. When I noticed that the program attempted to jump to 0x41414141, it confirmed control over the instruction pointer since 0x41 is the ASCII value of 'A'.

Step 2: Locating the win function

Since the binary is not stripped, symbol information is available. The address of the win function was found using:

readelf -s vuln | grep win

This revealed the exact address of win() within the binary. This address is the value that needs to overwrite the saved return address.

Step 3: Endianness 

On x86 systems, addresses are stored in little-endian format. So, I had to consider that  the bytes of the win function address must be reversed when included in the payload.

For example, if win() is located at:
0x080491f6

It must be written in memory as:
\xF6\x91\x04\x08

This conversion was necessary for the payload to work correctly.

Step 4: Developing the payload

The final payload I wrote consists of padding to fill the buffer and reach the return address, and the address of win() in little-endian format.

In Python, the payload was constructed as follows:

import struct

offset = 44
win_addr = struct.pack("<I", 0x080491f6)
payload = b"A" * offset + win_addr + b"\n"


The offset was determined experimentally, and struct.pack("<I", ...) ensures proper little-endian encoding. Finally, A newline is appended to simulate pressing Enter.

Step 5: Exploiting the remote service

The challenge provides a remote service accessible via nc. I automated interaction with this service via the Python script using the socket module. The script connects to the remote host and port, receives the prompt, sends the crafted payload, and receives the program outputs. After sending the payload, execution returned to the win() function, and the flag was printed:

picoCTF{addr3ss3s_ar3_3asy_b15b081e}

## Remediation

This vulnerability can be mitigated by multiple solutions:

1.Replacing unsafe functions like gets() with bounded alternatives such as fgets()
2. Enabling compiler protections
3. Validating and restricting user input sizes

# Sources/Credits

Written by Tatyana Ilieva

- https://play.picoctf.org/practice/challenge/258?page=1&search=buffer
- https://owasp.org/www-community/vulnerabilities/
- https://www.youtube.com/watch?v=k4hqdVo3cqk
