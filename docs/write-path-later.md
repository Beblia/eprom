# Write path (not implemented)

**UNTESTED AGAINST HARDWARE.** This file is a placeholder. The repo has no EEPROM write command, no `i2cset` wrapper, and no restore script.

Write stays blocked until Andrey has reviewed a successful read-only dump of that same board. The only restore that will be considered is byte-for-byte, onto the board the image came from, with an explicit confirmation step and a dry run. Cross-board copy and field editing stay out.

## Open questions

- **Write-protect pin.** S21 Pro / S21 XP may tie the EEPROM WC pin so the part ignores program cycles. Nobody has shown a public write of these chips. A reviewed dump does not answer the pin. The later design needs a way to observe WP before any program cycle, and it needs to stop when the pin is asserted.
- **Encryption.** D-Central says AES-128. Alex20129's S21+ path is AES-256-CBC. Neither is proven on our hardware. A raw same-board restore should not need the key. Changing a field, or moving an image onto a different board, is unproven. This repo does not contain keys and does not treat either cipher as solved.
- **Address width.** The read default is 256 bytes, 8-bit, because that is what skot/amlogic-cb-tools and Alex20129/eeprom_tool actually read. D-Central's S21-era table says AT24C16 or AT24C32. Sending a 16-bit pointer at an 8-bit chip stores the second byte. The write design has to wait until a dump's length and address width are confirmed on hardware (sysfs file size or the package marking).
- **Same image, same board.** The check that a restore file is the reviewed dump of the board in the socket is not designed yet. It has to be, before any write exists.
