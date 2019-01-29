#ifndef ED25519_EXT_H
#define ED25519_EXT_H

void ed25519_restore_from_private_key(unsigned char *public_key, const unsigned char *private_key);

#endif