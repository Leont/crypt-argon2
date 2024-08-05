#include "core.h"
#include "stdlib.h"

#ifdef HAVE_512BIT
void fill_segment_512bit(const argon2_instance_t *instance, argon2_position_t position);
#endif

#ifdef HAVE_256BIT
void fill_segment_256bit(const argon2_instance_t *instance, argon2_position_t position);
#endif

#ifdef HAVE_128BIT
void fill_segment_128bit(const argon2_instance_t *instance, argon2_position_t position);
#endif

void fill_segment_ref(const argon2_instance_t *instance, argon2_position_t position);

#ifdef HAVE_IFUNC
static void (*resolve_fill_segment(void))(const argon2_instance_t *instance, argon2_position_t position) {
	__builtin_cpu_init();
#ifdef HAVE_512BIT
	if (__builtin_cpu_supports("avx512f"))
		return fill_segment_512bit;
	else
#endif
#ifdef HAVE_256BIT
	if (__builtin_cpu_supports("avx2"))
		return fill_segment_256bit;
	else
#endif
#ifdef HAVE_128BIT
	if (__builtin_cpu_supports("sse3"))
		return fill_segment_128bit;
	else
#endif
	return fill_segment_ref;
}

void fill_segment(const argon2_instance_t *instance, argon2_position_t position) __attribute__ ((ifunc ("resolve_fill_segment")));
#else
void fill_segment(const argon2_instance_t *instance, argon2_position_t position) {
#ifdef HAVE_512BIT
	if (__builtin_cpu_supports("avx512f"))
		fill_segment_512bit(instance, position);
	else
#endif
#ifdef HAVE_256BIT
	if (__builtin_cpu_supports("avx2"))
		fill_segment_256bit(instance, position);
	else
#endif
#ifdef HAVE_128BIT
	if (__builtin_cpu_supports("sse3"))
		fill_segment_128bit(instance, position);
	else
#endif
	fill_segment_ref(instance, position);
}
#endif
