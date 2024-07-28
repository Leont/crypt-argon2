#include "core.h"
#include "stdlib.h"

#ifdef HAVE_AVX512
void fill_segment_avx512(const argon2_instance_t *instance, argon2_position_t position);
#endif

#ifdef HAVE_AVX2
void fill_segment_avx2(const argon2_instance_t *instance, argon2_position_t position);
#endif

#ifdef HAVE_SSE3
void fill_segment_sse3(const argon2_instance_t *instance, argon2_position_t position);
#endif

void fill_segment_ref(const argon2_instance_t *instance, argon2_position_t position);

#ifdef HAVE_SSE3
static void (*resolve_fill_segment(void))(const argon2_instance_t *instance, argon2_position_t position) {
	__builtin_cpu_init();
#ifdef HAVE_AVX512
	if (__builtin_cpu_supports("avx512f"))
		return fill_segment_avx512;
	else
#endif
#ifdef HAVE_AVX2
	if (__builtin_cpu_supports("avx2"))
		return fill_segment_avx2;
	else
#endif
	if (__builtin_cpu_supports("sse3"))
		return fill_segment_sse3;
	else
	return fill_segment_ref;
}

void fill_segment(const argon2_instance_t *instance, argon2_position_t position)
     __attribute__ ((ifunc ("resolve_fill_segment")));
#else
void fill_segment(const argon2_instance_t *instance, argon2_position_t position) {
	fill_segment_ref(instance, position);
}
#endif
