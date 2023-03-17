/*
 *
 * Copyright 2021-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "srsran/srsvec/conversion.h"

#include "simd.h"

using namespace srsran;
using namespace srsvec;

static inline void convert_fi_simd(const float* x, int16_t* z, float scale, unsigned len)
{
  unsigned i = 0;

#if SRSRAN_SIMD_F_SIZE && SRSRAN_SIMD_S_SIZE
  simd_f_t s = srsran_simd_f_set1(scale);
  if (SIMD_IS_ALIGNED(x) && SIMD_IS_ALIGNED(z)) {
    for (; i + SRSRAN_SIMD_S_SIZE < len + 1; i += SRSRAN_SIMD_S_SIZE) {
      simd_f_t a = srsran_simd_f_load(&x[i]);
      simd_f_t b = srsran_simd_f_load(&x[i + SRSRAN_SIMD_F_SIZE]);

      simd_f_t sa = srsran_simd_f_mul(a, s);
      simd_f_t sb = srsran_simd_f_mul(b, s);

      simd_s_t i16 = srsran_simd_convert_2f_s(sa, sb);

      srsran_simd_s_store(&z[i], i16);
    }
  } else {
    for (; i + SRSRAN_SIMD_S_SIZE < len + 1; i += SRSRAN_SIMD_S_SIZE) {
      simd_f_t a = srsran_simd_f_loadu(&x[i]);
      simd_f_t b = srsran_simd_f_loadu(&x[i + SRSRAN_SIMD_F_SIZE]);

      simd_f_t sa = srsran_simd_f_mul(a, s);
      simd_f_t sb = srsran_simd_f_mul(b, s);

      simd_s_t i16 = srsran_simd_convert_2f_s(sa, sb);

      srsran_simd_s_storeu(&z[i], i16);
    }
  }
#endif /* SRSRAN_SIMD_F_SIZE && SRSRAN_SIMD_S_SIZE */

  for (; i < len; i++) {
    z[i] = (int16_t)(x[i] * scale);
  }
}

static inline void convert_if_simd(const int16_t* x, float* z, float scale, unsigned len)
{
  unsigned    i    = 0;
  const float gain = 1.0f / scale;

#ifdef mHAVE_SSE
  __m128 s = _mm_set1_ps(gain);
  if (SIMD_IS_ALIGNED(z)) {
    for (; i < len - 3; i += 4) {
      __m64* ptr = (__m64*)&x[i];
      __m128 fl  = _mm_cvtpi16_ps(*ptr);
      __m128 v   = _mm_mul_ps(fl, s);

      _mm_store_ps(&z[i], v);
    }
  } else {
    for (; i < len - 3; i += 4) {
      __m64* ptr = (__m64*)&x[i];
      __m128 fl  = _mm_cvtpi16_ps(*ptr);
      __m128 v   = _mm_mul_ps(fl, s);

      _mm_storeu_ps(&z[i], v);
    }
  }
#endif /* HAVE_SSE */

  for (; i < len; i++) {
    z[i] = ((float)x[i]) * gain;
  }
}

void srsran::srsvec::convert(span<const cf_t> x, float scale, span<int16_t> z)
{
  assert(2 * x.size() == z.size());

  convert_fi_simd((const float*)x.data(), z.data(), scale, z.size());
}

void srsran::srsvec::convert_swap(span<const cf_t> x, float scale, span<int16_t> z)
{
  assert(2 * x.size() == z.size());

  convert_fi_simd((const float*)x.data(), z.data(), scale, z.size());

  // Perform I/Q swap
  for (unsigned i = 0; i != z.size(); i += 2) {
    int16_t temp = z[i];
    z[i]         = z[i + 1];
    z[i + 1]     = temp;
  }
}

void srsran::srsvec::convert(span<const int16_t> x, float scale, span<cf_t> z)
{
  assert(x.size() == 2 * z.size());

  convert_if_simd(x.data(), (float*)z.data(), scale, x.size());
}

void srsran::srsvec::convert_swap(span<const int16_t> x, float scale, span<cf_t> z)
{
  assert(x.size() == 2 * z.size());

  convert_if_simd(x.data(), (float*)z.data(), scale, x.size());

  // Perform I/Q swap
  for (unsigned i = 0; i != z.size(); i++) {
    cf_t temp = z[i];
    z[i]      = {temp.imag(), temp.real()};
  }
}

void srsran::srsvec::convert(span<const float> x, float scale, span<int16_t> z)
{
  assert(x.size() == z.size());

  convert_fi_simd(x.data(), z.data(), scale, z.size());
}

void srsran::srsvec::convert(span<const int16_t> x, float scale, span<float> z)
{
  assert(x.size() == z.size());

  convert_if_simd(x.data(), z.data(), scale, z.size());
}