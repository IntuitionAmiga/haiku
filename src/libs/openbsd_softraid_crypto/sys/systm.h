#ifndef OPENBSD_SOFTRAID_CRYPTO_SYS_SYSTM_H
#define OPENBSD_SOFTRAID_CRYPTO_SYS_SYSTM_H


#include <stdint.h>
#include <string.h>

typedef unsigned char u_char;
typedef unsigned int u_int;
typedef uint8_t u_int8_t;

static inline void
openbsd_softraid_explicit_bzero(void* buffer, size_t length)
{
	volatile uint8_t* bytes = (volatile uint8_t*)buffer;
	while (length-- > 0)
		*bytes++ = 0;
}

#ifndef explicit_bzero
#define explicit_bzero(buffer, length) \
	openbsd_softraid_explicit_bzero((buffer), (length))
#endif


#ifndef bcopy
#define bcopy(source, destination, length) memmove((destination), (source), (length))
#endif

#ifndef bzero
#define bzero(buffer, length) memset((buffer), 0, (length))
#endif

#endif /* OPENBSD_SOFTRAID_CRYPTO_SYS_SYSTM_H */
