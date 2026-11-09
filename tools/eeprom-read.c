/*
 * UNTESTED AGAINST HARDWARE.
 *
 * Read-only AT24Cxx dump for a VNish miner that has no i2c-tools.
 * Build a static aarch64 binary on a cross toolchain and pass it to
 * dump_eeprom.py with --reader and --allow-tmp-upload.
 *
 * Each chunk is an I2C_RDWR pair: a write of only the word-address
 * byte(s), then a read. No data byte is ever queued. Linux i2c-dev
 * requires O_RDWR to issue that ioctl; the open mode is not a chip write.
 *
 * On an 8-bit part (24C02 and anything else that takes one address
 * byte), a two-byte "pointer" stores the second byte. This program
 * sends two address bytes only when argv ends with confirm-16bit.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

enum { CHUNK = 32, MAX_LEN = 8192 };

static void usage(void) {
  fprintf(stderr,
          "usage: eeprom-read <bus> <addr> <length> <addr-bytes> [confirm-16bit]\n"
          "  bus        0-7 (i2c-dev number, not a path)\n"
          "  addr       0x50, 0x51, or 0x52\n"
          "  length     256 with 1 address byte; 512..8192 with confirm-16bit\n"
          "  addr-bytes 1 or 2\n"
          "stdout is raw bytes. This program has no write command.\n");
}

static int parse_u(const char *text, unsigned long *out) {
  char *end = NULL;
  unsigned long value;

  errno = 0;
  value = strtoul(text, &end, 0);
  if (errno != 0 || end == text || *end != '\0') {
    return -1;
  }
  *out = value;
  return 0;
}

static int read_chunk(int fd, unsigned addr, unsigned offset, unsigned addr_bytes,
                      unsigned chunk, uint8_t *dst) {
  uint8_t pointer[2];
  struct i2c_msg msgs[2];
  struct i2c_rdwr_ioctl_data xfer;

  if (addr_bytes == 1) {
    pointer[0] = (uint8_t)offset;
  } else {
    pointer[0] = (uint8_t)((offset >> 8) & 0xff);
    pointer[1] = (uint8_t)(offset & 0xff);
  }

  memset(msgs, 0, sizeof msgs);
  msgs[0].addr = (uint16_t)addr;
  msgs[0].flags = 0;
  msgs[0].len = (uint16_t)addr_bytes;
  msgs[0].buf = pointer;
  msgs[1].addr = (uint16_t)addr;
  msgs[1].flags = I2C_M_RD;
  msgs[1].len = (uint16_t)chunk;
  msgs[1].buf = dst;

  xfer.msgs = msgs;
  xfer.nmsgs = 2;
  if (ioctl(fd, I2C_RDWR, &xfer) < 0) {
    return -1;
  }
  return 0;
}

int main(int argc, char **argv) {
  unsigned long bus = 0;
  unsigned long addr = 0;
  unsigned long length = 0;
  unsigned long addr_bytes = 0;
  int confirm = 0;
  char path[32];
  int fd = -1;
  uint8_t *buffer = NULL;
  unsigned offset;
  int rc = 1;

  if (argc != 5 && argc != 6) {
    usage();
    return 2;
  }
  if (parse_u(argv[1], &bus) != 0 || parse_u(argv[2], &addr) != 0 ||
      parse_u(argv[3], &length) != 0 || parse_u(argv[4], &addr_bytes) != 0) {
    usage();
    return 2;
  }
  if (argc == 6) {
    if (strcmp(argv[5], "confirm-16bit") != 0) {
      usage();
      return 2;
    }
    confirm = 1;
  }

  if (bus > 7 || (addr != 0x50 && addr != 0x51 && addr != 0x52)) {
    fprintf(stderr, "bus must be 0-7 and addr must be 0x50, 0x51, or 0x52\n");
    return 2;
  }
  if (addr_bytes == 1) {
    if (confirm || length != 256) {
      fprintf(stderr, "8-bit mode reads exactly 256 bytes and rejects confirm-16bit\n");
      return 2;
    }
  } else if (addr_bytes == 2) {
    if (!confirm || length < 512 || length > MAX_LEN) {
      fprintf(stderr, "16-bit mode needs confirm-16bit and length 512..8192\n");
      return 2;
    }
  } else {
    fprintf(stderr, "addr-bytes must be 1 or 2\n");
    return 2;
  }

  if (snprintf(path, sizeof path, "/dev/i2c-%lu", bus) >= (int)sizeof path) {
    fprintf(stderr, "bus path overflow\n");
    return 2;
  }

  buffer = calloc(length, 1);
  if (buffer == NULL) {
    perror("calloc");
    return 1;
  }

  fd = open(path, O_RDWR);
  if (fd < 0) {
    perror(path);
    free(buffer);
    return 1;
  }

  for (offset = 0; offset < length;) {
    unsigned chunk = length - offset;
    if (chunk > CHUNK) {
      chunk = CHUNK;
    }
    if (read_chunk(fd, (unsigned)addr, offset, (unsigned)addr_bytes, chunk,
                   buffer + offset) != 0) {
      perror("I2C_RDWR");
      goto done;
    }
    offset += chunk;
  }

  if (fwrite(buffer, 1, length, stdout) != length) {
    perror("fwrite");
    goto done;
  }
  rc = 0;

done:
  close(fd);
  free(buffer);
  return rc;
}
