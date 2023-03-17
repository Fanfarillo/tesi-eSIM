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

#include "srsran/adt/bounded_bitset.h"
#include "srsran/support/test_utils.h"
#include <gtest/gtest.h>
#include <random>

// Disable GCC 5's -Wsuggest-override warnings in gtest.
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wall"
#else // __clang__
#pragma GCC diagnostic ignored "-Wsuggest-override"
#endif // __clang__

using namespace srsran;

std::random_device rd;
std::mt19937       g(rd());

template <typename T>
class bitmask_tester : public ::testing::Test
{
protected:
  using Integer                    = T;
  static constexpr size_t nof_bits = sizeof(Integer) * 8U;
};
using mask_integer_types = ::testing::Types<uint8_t, uint16_t, uint32_t, uint64_t>;
TYPED_TEST_SUITE(bitmask_tester, mask_integer_types);

TYPED_TEST(bitmask_tester, lsb_ones)
{
  using IntegerType = typename TestFixture::Integer;
  // sanity checks.
  ASSERT_EQ(0, mask_lsb_ones<IntegerType>(0));
  ASSERT_EQ(static_cast<IntegerType>(-1), mask_lsb_ones<IntegerType>(this->nof_bits))
      << "for nof_bits=" << (unsigned)this->nof_bits;
  ASSERT_EQ(0b11, mask_lsb_ones<IntegerType>(2));

  // test all combinations.
  for (unsigned nof_ones = 0; nof_ones != this->nof_bits; ++nof_ones) {
    IntegerType expected = (static_cast<uint64_t>(1U) << nof_ones) - 1U;
    ASSERT_EQ(expected, mask_lsb_ones<IntegerType>(nof_ones)) << "for nof_ones=" << nof_ones;
  }
}

TYPED_TEST(bitmask_tester, lsb_zeros)
{
  using IntegerType = typename TestFixture::Integer;
  // sanity checks.
  ASSERT_EQ((IntegerType)-1, mask_lsb_zeros<IntegerType>(0));
  ASSERT_EQ(0, mask_lsb_zeros<IntegerType>(this->nof_bits));

  // test all combinations.
  for (unsigned nof_zeros = 0; nof_zeros != this->nof_bits; ++nof_zeros) {
    IntegerType expected = (static_cast<uint64_t>(1U) << nof_zeros) - 1U;
    expected             = ~expected;
    ASSERT_EQ(expected, mask_lsb_zeros<IntegerType>(nof_zeros)) << "for nof_zeros=" << nof_zeros;
    ASSERT_EQ((IntegerType)~mask_lsb_ones<IntegerType>(nof_zeros), mask_lsb_zeros<IntegerType>(nof_zeros));
  }
}

TYPED_TEST(bitmask_tester, msb_ones)
{
  using IntegerType = typename TestFixture::Integer;
  // sanity checks.
  ASSERT_EQ(0, mask_msb_ones<IntegerType>(0));
  ASSERT_EQ(static_cast<IntegerType>(-1), mask_msb_ones<IntegerType>(this->nof_bits));

  // test all combinations.
  for (unsigned nof_ones = 0; nof_ones != this->nof_bits; ++nof_ones) {
    IntegerType expected = 0;
    if (nof_ones > 0) {
      unsigned nof_lsb_zeros = this->nof_bits - nof_ones;
      expected               = ~((static_cast<IntegerType>(1U) << (nof_lsb_zeros)) - 1U);
    }
    ASSERT_EQ(expected, mask_msb_ones<IntegerType>(nof_ones)) << "for nof_ones=" << nof_ones;
  }
}

TYPED_TEST(bitmask_tester, msb_zeros)
{
  using IntegerType = typename TestFixture::Integer;
  // sanity checks.
  ASSERT_EQ((IntegerType)-1, mask_msb_zeros<IntegerType>(0));
  ASSERT_EQ(0, mask_msb_zeros<IntegerType>(this->nof_bits));

  // test all combinations.
  for (unsigned nof_zeros = 0; nof_zeros != this->nof_bits; ++nof_zeros) {
    IntegerType expected = 0;
    if (nof_zeros > 0) {
      unsigned nof_lsb_ones = this->nof_bits - nof_zeros;
      expected              = ~((static_cast<IntegerType>(1U) << (nof_lsb_ones)) - 1U);
    }
    expected = ~expected;
    ASSERT_EQ(expected, mask_msb_zeros<IntegerType>(nof_zeros)) << "for nof_zeros=" << nof_zeros;
    ASSERT_EQ((IntegerType)~mask_lsb_ones<IntegerType>(nof_zeros), mask_lsb_zeros<IntegerType>(nof_zeros));
  }
}

TYPED_TEST(bitmask_tester, first_lsb_one)
{
  using IntegerType = typename TestFixture::Integer;
  std::uniform_int_distribution<IntegerType> rd_int{0, std::numeric_limits<IntegerType>::max()};

  // sanity checks.
  ASSERT_EQ(std::numeric_limits<IntegerType>::digits, find_first_lsb_one<IntegerType>(0));
  ASSERT_EQ(0, find_first_lsb_one<IntegerType>(-1));
  ASSERT_EQ(0, find_first_lsb_one<IntegerType>(0b1));
  ASSERT_EQ(1, find_first_lsb_one<IntegerType>(0b10));
  ASSERT_EQ(0, find_first_lsb_one<IntegerType>(0b11));

  // test all combinations.
  for (unsigned one_idx = 0; one_idx != this->nof_bits - 1; ++one_idx) {
    IntegerType mask  = mask_lsb_zeros<IntegerType>(one_idx);
    IntegerType value = rd_int(g) & mask;

    ASSERT_EQ(find_first_lsb_one(mask), one_idx);
    ASSERT_GE(find_first_lsb_one(value), one_idx) << fmt::format("for value {:#b}", value);
  }
}

TYPED_TEST(bitmask_tester, first_msb_one)
{
  using IntegerType = typename TestFixture::Integer;
  std::uniform_int_distribution<IntegerType> rd_int{0, std::numeric_limits<IntegerType>::max()};

  // sanity checks.
  ASSERT_EQ(std::numeric_limits<IntegerType>::digits, find_first_msb_one<IntegerType>(0));
  ASSERT_EQ(this->nof_bits - 1, find_first_msb_one<IntegerType>(-1));
  ASSERT_EQ(0, find_first_msb_one<IntegerType>(0b1));
  ASSERT_EQ(1, find_first_msb_one<IntegerType>(0b10));
  ASSERT_EQ(1, find_first_msb_one<IntegerType>(0b11));

  // test all combinations.
  for (unsigned one_idx = 0; one_idx != this->nof_bits - 1; ++one_idx) {
    IntegerType mask  = mask_lsb_ones<IntegerType>(one_idx + 1);
    IntegerType value = std::max((IntegerType)(rd_int(g) & mask), (IntegerType)1U);

    ASSERT_EQ(one_idx, find_first_msb_one(mask));
    ASSERT_LE(find_first_msb_one(value), one_idx) << fmt::format("for value {:#b}", value);
  }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

template <typename BoundedBitset>
class bounded_bitset_tester : public ::testing::Test
{
protected:
  using bitset_type = BoundedBitset;

  static constexpr unsigned max_size() { return bitset_type::max_size(); }

  unsigned get_random_size() const { return std::uniform_int_distribution<unsigned>{1, bitset_type::max_size()}(g); }

  bitset_type create_bitset_with_zeros(unsigned size) const { return bitset_type(size); }

  static bitset_type create_bitset_with_ones(unsigned size)
  {
    std::vector<bool> data(size, true);
    return bitset_type(data.begin(), data.end());
  }

  static bitset_type create_random_bitset(unsigned size)
  {
    std::vector<bool> data(size);
    for (auto it = data.begin(); it != data.end(); ++it) {
      *it = std::bernoulli_distribution{}(g);
    }
    return bitset_type(data.begin(), data.end());
  }

  static std::vector<bool> create_random_vector(unsigned size)
  {
    std::vector<bool> vec(size);
    for (auto it = vec.begin(); it != vec.end(); ++it) {
      *it = std::bernoulli_distribution{}(g);
    }
    return vec;
  }
};
using bitset_types = ::testing::Types<bounded_bitset<25>,
                                      bounded_bitset<25, true>,
                                      bounded_bitset<120>,
                                      bounded_bitset<120, true>,
                                      bounded_bitset<512>,
                                      bounded_bitset<512, true>>;
TYPED_TEST_SUITE(bounded_bitset_tester, bitset_types);

TYPED_TEST(bounded_bitset_tester, all_zeros)
{
  auto zero_mask = this->create_bitset_with_zeros(this->get_random_size());
  ASSERT_GT(zero_mask.size(), 0);
  ASSERT_EQ(0, zero_mask.count());
  ASSERT_TRUE(zero_mask.none());
  ASSERT_FALSE(zero_mask.any());
  ASSERT_FALSE(zero_mask.all());
}

TYPED_TEST(bounded_bitset_tester, empty_bitset)
{
  auto zero_sized_mask = this->create_bitset_with_zeros(0);
  ASSERT_EQ(this->max_size(), zero_sized_mask.max_size());
  ASSERT_EQ(0, zero_sized_mask.size());
  ASSERT_EQ(0, zero_sized_mask.count());
  ASSERT_TRUE(zero_sized_mask.none());
  ASSERT_FALSE(zero_sized_mask.any());
  ASSERT_TRUE(zero_sized_mask.all());

  zero_sized_mask.flip();
  ASSERT_TRUE(zero_sized_mask.none()) << "Flipping empty bitset should be a no-op";
  ASSERT_EQ(0, zero_sized_mask.size()) << "Flipping empty bitset should be a no-op";

  auto zero_mask = this->create_bitset_with_zeros(this->get_random_size());
  ASSERT_NE(zero_mask, zero_sized_mask);
  zero_sized_mask.resize(zero_mask.size());
  ASSERT_EQ(zero_mask, zero_sized_mask);
}

TYPED_TEST(bounded_bitset_tester, initializer_list_constructor)
{
  typename TestFixture::bitset_type bitmap = {true, true, true, true, false};
  ASSERT_EQ(bitmap.size(), 5);
  ASSERT_TRUE(bitmap.test(0));
  ASSERT_TRUE(bitmap.test(1));
  ASSERT_TRUE(bitmap.test(3));
  ASSERT_FALSE(bitmap.test(4));
}

TYPED_TEST(bounded_bitset_tester, iterator_constructor)
{
  std::vector<bool>                 data = this->create_random_vector(this->get_random_size());
  typename TestFixture::bitset_type bitmap(data.begin(), data.end());
  ASSERT_EQ(bitmap.size(), data.size());

  for (unsigned i = 0; i != data.size(); ++i) {
    ASSERT_EQ(data[i], bitmap.test(i));
  }
}

TYPED_TEST(bounded_bitset_tester, all_ones)
{
  typename TestFixture::bitset_type ones_bitmap = this->create_bitset_with_ones(this->get_random_size());

  ASSERT_TRUE(ones_bitmap.all());
  ASSERT_TRUE(ones_bitmap.any());
  ASSERT_FALSE(ones_bitmap.none());
  ASSERT_EQ(ones_bitmap.size(), ones_bitmap.count());
}

TYPED_TEST(bounded_bitset_tester, flip)
{
  auto bitmap          = this->create_random_bitset(this->get_random_size());
  auto original_bitmap = bitmap;
  bitmap.flip();

  ASSERT_GT(bitmap.size(), 0);
  ASSERT_EQ(bitmap.size(), original_bitmap.size());
  for (unsigned i = 0; i != bitmap.size(); ++i) {
    ASSERT_NE(bitmap.test(i), original_bitmap.test(i));
  }
}

TYPED_TEST(bounded_bitset_tester, set_bit)
{
  std::vector<bool>                 data = this->create_random_vector(this->get_random_size());
  typename TestFixture::bitset_type bitmap(data.size());
  typename TestFixture::bitset_type expected_bitmap(data.begin(), data.end());

  for (unsigned i = 0; i != data.size(); ++i) {
    if (data[i]) {
      bitmap.set(i);
    }
  }
  ASSERT_EQ(bitmap, expected_bitmap) << fmt::format("failed {} != {}", bitmap, expected_bitmap);
}

TYPED_TEST(bounded_bitset_tester, bitwise_or)
{
  typename TestFixture::bitset_type bitmap       = this->create_random_bitset(this->get_random_size());
  typename TestFixture::bitset_type zeros_bitmap = this->create_bitset_with_zeros(bitmap.size());
  typename TestFixture::bitset_type ones_bitmap  = this->create_bitset_with_ones(bitmap.size());

  ASSERT_EQ(bitmap | bitmap, bitmap);
  ASSERT_EQ(bitmap | zeros_bitmap, bitmap);
  ASSERT_EQ(zeros_bitmap | bitmap, bitmap);
  ASSERT_EQ(bitmap | ones_bitmap, ones_bitmap);
  ASSERT_EQ(ones_bitmap | bitmap, ones_bitmap);

  auto flipped_bitmap = bitmap;
  flipped_bitmap.flip();
  ASSERT_EQ(flipped_bitmap | bitmap, this->create_bitset_with_ones(bitmap.size()));
  ASSERT_EQ(bitmap | flipped_bitmap, this->create_bitset_with_ones(bitmap.size()));

  bitmap |= flipped_bitmap;
  ASSERT_EQ(bitmap, this->create_bitset_with_ones(bitmap.size()));
}

TYPED_TEST(bounded_bitset_tester, bitwise_and)
{
  typename TestFixture::bitset_type bitmap       = this->create_random_bitset(this->get_random_size());
  typename TestFixture::bitset_type zeros_bitmap = this->create_bitset_with_zeros(bitmap.size());
  typename TestFixture::bitset_type ones_bitmap  = this->create_bitset_with_ones(bitmap.size());

  ASSERT_EQ(bitmap & bitmap, bitmap);
  ASSERT_EQ(bitmap & zeros_bitmap, zeros_bitmap);
  ASSERT_EQ(zeros_bitmap & bitmap, zeros_bitmap);
  ASSERT_EQ(bitmap & ones_bitmap, bitmap);
  ASSERT_EQ(ones_bitmap & bitmap, bitmap);

  auto flipped_bitmap = bitmap;
  flipped_bitmap.flip();
  ASSERT_EQ(flipped_bitmap & bitmap, this->create_bitset_with_zeros(bitmap.size()));
  ASSERT_EQ(bitmap & flipped_bitmap, this->create_bitset_with_zeros(bitmap.size()));

  bitmap &= flipped_bitmap;
  ASSERT_EQ(bitmap, this->create_bitset_with_zeros(bitmap.size()));
}

TYPED_TEST(bounded_bitset_tester, any_range)
{
  std::vector<bool>                 vec = this->create_random_vector(this->get_random_size());
  typename TestFixture::bitset_type bitmap(vec.begin(), vec.end());

  for (unsigned l = 1; l < vec.size(); ++l) {
    for (unsigned i = 0; i < vec.size() - l; ++i) {
      bool expected_val = false;
      for (unsigned j = 0; j != l; ++j) {
        if (vec[i + j]) {
          expected_val = true;
          break;
        }
      }
      ASSERT_EQ(expected_val, bitmap.any(i, i + l))
          << fmt::format("For bitmap={:x} of size={} in [{}, {})", bitmap, bitmap.size(), i, i + l);
    }
  }
}

TYPED_TEST(bounded_bitset_tester, all_range)
{
  std::vector<bool>                 vec = this->create_random_vector(this->get_random_size());
  typename TestFixture::bitset_type bitmap(vec.begin(), vec.end());

  for (unsigned l = 1; l < vec.size(); ++l) {
    for (unsigned i = 0; i < vec.size() - l; ++i) {
      bool expected_val = true;
      for (unsigned j = 0; j != l; ++j) {
        if (not vec[i + j]) {
          expected_val = false;
          break;
        }
      }
      ASSERT_EQ(expected_val, bitmap.all(i, i + l))
          << fmt::format("For bitmap={:x} of size={} in [{}, {})", bitmap, bitmap.size(), i, i + l);
    }
  }
}

TYPED_TEST(bounded_bitset_tester, fill_ones)
{
  unsigned   bitset_size  = this->get_random_size();
  const auto zeros_bitmap = this->create_bitset_with_zeros(bitset_size);

  for (unsigned l = 1; l < bitset_size; ++l) {
    for (unsigned i = 0; i < bitset_size - l; ++i) {
      auto bitmap = zeros_bitmap;
      bitmap.fill(i, i + l);
      ASSERT_FALSE(bitmap.any(0, i));
      ASSERT_TRUE(bitmap.all(i, i + l)) << fmt::format(
          "For bitmap={:x} of size={} in [{}, {})", bitmap, bitmap.size(), i, i + l);
      ASSERT_FALSE(bitmap.any(i + l, bitset_size));
    }
  }
}

TYPED_TEST(bounded_bitset_tester, fill_zeros)
{
  unsigned   bitset_size = this->get_random_size();
  const auto ones_bitmap = this->create_bitset_with_ones(bitset_size);

  for (unsigned l = 1; l < bitset_size; ++l) {
    for (unsigned i = 0; i < bitset_size - l; ++i) {
      auto bitmap = ones_bitmap;
      bitmap.fill(i, i + l, false);
      ASSERT_TRUE(bitmap.all(0, i)) << fmt::format(
          "For bitmap={:x} of size={} in [{}, {})", bitmap, bitmap.size(), i, i + l);
      ASSERT_FALSE(bitmap.any(i, i + l));
      ASSERT_TRUE(bitmap.all(i + l, bitset_size))
          << fmt::format("For bitmap={:x} of size={} in [{}, {})", bitmap, bitmap.size(), i, i + l);
    }
  }
}

TYPED_TEST(bounded_bitset_tester, slice)
{
  using big_bitset_type                   = typename TestFixture::bitset_type;
  unsigned                big_bitset_size = this->get_random_size();
  const std::vector<bool> vec             = this->create_random_vector(big_bitset_size);
  big_bitset_type         big_bitmap(vec.begin(), vec.end());

  constexpr size_t N_small = TestFixture::bitset_type::max_size() / 2;
  using small_bitset_type  = bounded_bitset<N_small, big_bitset_type::bit_order()>;
  unsigned small_bitset_size =
      std::uniform_int_distribution<unsigned>{0, std::min((unsigned)N_small, big_bitset_size - 1)}(g);
  unsigned offset     = std::uniform_int_distribution<unsigned>{0, small_bitset_size}(g);
  unsigned end_offset = std::uniform_int_distribution<unsigned>{offset, small_bitset_size}(g);

  small_bitset_type small_bitmap = big_bitmap.template slice<N_small>(offset, end_offset);
  ASSERT_EQ(end_offset - offset, small_bitmap.size());

  for (unsigned i = 0; i != small_bitmap.size(); ++i) {
    ASSERT_EQ(small_bitmap.test(i), big_bitmap.test(i + offset))
        << fmt::format("For slice={} of size={} taken from [{}, {}) of big_bitmap={} of size={}",
                       small_bitmap,
                       small_bitmap.size(),
                       offset,
                       end_offset,
                       big_bitmap,
                       big_bitmap.size());
  }
}

TEST(BoundedBitset, integer_bitset_conversion)
{
  unsigned           bitset_size = 23;
  unsigned           nof_ones    = std::uniform_int_distribution<unsigned>{1, bitset_size}(g);
  unsigned           integermask = mask_lsb_ones<unsigned>(nof_ones);
  bounded_bitset<25> mask(bitset_size);
  mask.from_uint64(integermask);

  ASSERT_EQ(bitset_size, mask.size());
  ASSERT_EQ(nof_ones, mask.count());
  ASSERT_TRUE(mask.any());
  ASSERT_FALSE(mask.none());
  ASSERT_EQ(integermask, mask.to_uint64());
}

TEST(BoundedBitset, setting_bit)
{
  bounded_bitset<25> mask(23);
  mask.set(10);

  ASSERT_TRUE(mask.any());
  ASSERT_TRUE(mask.all(10, 11));
  ASSERT_TRUE(not mask.all(10, 12));
  ASSERT_TRUE(not mask.all());
  ASSERT_TRUE(not mask.test(0));
  ASSERT_TRUE(mask.test(10));
  mask.flip();
  ASSERT_TRUE(not mask.test(10));
  ASSERT_TRUE(mask.test(0));

  bounded_bitset<25> mask1(25);
  mask1.set(10);
  mask1.set(11);
  mask1.set(12);
  mask1.set(13);
  mask1.set(14);
  ASSERT_TRUE(mask1.all(10, 15));
  ASSERT_TRUE(not mask1.all(10, 16));
  ASSERT_TRUE(not mask1.all(9, 15));
  ASSERT_TRUE(mask1.any(10, 15));
  ASSERT_TRUE(mask1.any());

  bounded_bitset<25> mask2(25);
  mask2.set(0);
  mask2.set(1);
  mask2.set(2);
  mask2.set(3);
  mask2.set(4);
  ASSERT_TRUE(mask2.all(0, 5));
  ASSERT_TRUE(not mask2.all(0, 6));
  ASSERT_TRUE(mask2.any(0, 5));
  ASSERT_TRUE(mask2.any());

  bounded_bitset<25> mask3(25);
  mask3.set(20);
  mask3.set(21);
  mask3.set(22);
  mask3.set(23);
  mask3.set(24);
  ASSERT_TRUE(mask3.all(20, 25));
  ASSERT_TRUE(not mask3.all(19, 25));
  ASSERT_TRUE(mask3.any(20, 25));
  ASSERT_TRUE(mask3.any());
}

TEST(BoundedBitset, bitwise_format)
{
  {
    bounded_bitset<100> bitset(100);
    bitset.set(0);
    bitset.set(5);

    ASSERT_TRUE(fmt::format("{:x}", bitset) == "0000000000000000000000021");
    ASSERT_TRUE(fmt::format("{:b}", bitset) ==
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100001");
    ASSERT_TRUE(fmt::format("{:br}", bitset) ==
                "1000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    bitset.set(99);
    ASSERT_TRUE(fmt::format("{:x}", bitset) == "8000000000000000000000021");
    ASSERT_TRUE(fmt::format("{:b}", bitset) ==
                "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100001");
    ASSERT_TRUE(fmt::format("{:br}", bitset) ==
                "1000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001");
  }

  {
    bounded_bitset<100> bitset(25);
    bitset.set(0);
    bitset.set(4);

    ASSERT_TRUE(fmt::format("{:x}", bitset) == "0000011");
    ASSERT_TRUE(fmt::format("{:b}", bitset) == "0000000000000000000010001");
    ASSERT_TRUE(fmt::format("{:br}", bitset) == "1000100000000000000000000");

    bitset.set(24);
    ASSERT_TRUE(fmt::format("{:x}", bitset) == "1000011");
    ASSERT_TRUE(fmt::format("{:b}", bitset) == "1000000000000000000010001");
    ASSERT_TRUE(fmt::format("{:br}", bitset) == "1000100000000000000000001");
  }

  {
    bounded_bitset<100, true> bitset(100);
    bitset.set(0);
    bitset.set(5);

    ASSERT_TRUE(fmt::format("{:x}", bitset) == "8400000000000000000000000");
    ASSERT_TRUE(fmt::format("{:b}", bitset) ==
                "1000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    ASSERT_TRUE(fmt::format("{:br}", bitset) ==
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100001");

    bitset.set(99);
    ASSERT_TRUE(fmt::format("{:x}", bitset) == "8400000000000000000000001");
    ASSERT_TRUE(fmt::format("{:b}", bitset) ==
                "1000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001");
    ASSERT_TRUE(fmt::format("{:br}", bitset) ==
                "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100001");
  }
}

TEST(BoundedBitset, bitwise_resize)
{
  {
    bounded_bitset<100> bitset;
    ASSERT_TRUE(bitset.none() and bitset.size() == 0);

    bitset.resize(100);
    ASSERT_TRUE(bitset.none() and bitset.size() == 100);
    bitset.fill(0, 100);
    ASSERT_TRUE(bitset.all() and bitset.size() == 100);

    bitset.resize(25);
    ASSERT_TRUE(bitset.to_uint64() == 0x1ffffff);
    ASSERT_TRUE(bitset.all() and bitset.size() == 25); // keeps the data it had for the non-erased bits

    bitset.resize(100);
    ASSERT_TRUE(bitset.count() == 25 and bitset.size() == 100);
  }

  {
    // TEST: Reverse case
    bounded_bitset<100, true> bitset;
    ASSERT_TRUE(bitset.none() and bitset.size() == 0);

    bitset.resize(100);
    ASSERT_TRUE(bitset.none() and bitset.size() == 100);
    bitset.fill(0, 100);
    ASSERT_TRUE(bitset.all() and bitset.size() == 100);

    bitset.resize(25);
    ASSERT_TRUE(bitset.to_uint64() == 0x1ffffff);
    ASSERT_TRUE(bitset.all() and bitset.size() == 25); // keeps the data it had for the non-erased bits

    bitset.resize(100);
    ASSERT_TRUE(bitset.count() == 25 and bitset.size() == 100);
  }
}

template <bool reversed>
void test_bitset_find()
{
  {
    bounded_bitset<25, reversed> bitset(6);

    // 0b000000
    ASSERT_TRUE(bitset.find_lowest(0, bitset.size(), false) == 0);
    ASSERT_TRUE(bitset.find_lowest(0, bitset.size(), true) == -1);

    // 0b000100
    bitset.set(2);
    ASSERT_TRUE(bitset.find_lowest(0, 6) == 2);
    ASSERT_TRUE(bitset.find_lowest(0, 6, false) == 0);
    ASSERT_TRUE(bitset.find_lowest(3, 6) == -1);
    ASSERT_TRUE(bitset.find_lowest(3, 6, false) == 3);

    // 0b000101
    bitset.set(0);
    ASSERT_TRUE(bitset.find_lowest(0, 6) == 0);
    ASSERT_TRUE(bitset.find_lowest(0, 6, false) == 1);
    ASSERT_TRUE(bitset.find_lowest(3, 6) == -1);
    ASSERT_TRUE(bitset.find_lowest(3, 6, false) == 3);

    // 0b100101
    bitset.set(5);
    ASSERT_TRUE(bitset.find_lowest(0, 6) == 0);
    ASSERT_TRUE(bitset.find_lowest(0, 6, false) == 1);
    ASSERT_TRUE(bitset.find_lowest(3, 6) == 5);

    // 0b111111
    bitset.fill(0, 6);
    ASSERT_TRUE(bitset.find_lowest(0, 6) == 0);
    ASSERT_TRUE(bitset.find_lowest(0, 6, false) == -1);
    ASSERT_TRUE(bitset.find_lowest(3, 6, false) == -1);
  }
  {
    bounded_bitset<100, reversed> bitset(95);

    // 0b0...0
    ASSERT_TRUE(bitset.find_lowest(0, bitset.size()) == -1);

    // 0b1000...
    bitset.set(94);
    ASSERT_TRUE(bitset.find_lowest(0, 93) == -1);
    ASSERT_TRUE(bitset.find_lowest(0, bitset.size()) == 94);

    // 0b1000...010
    bitset.set(1);
    ASSERT_TRUE(bitset.find_lowest(0, bitset.size()) == 1);
    ASSERT_TRUE(bitset.find_lowest(1, bitset.size()) == 1);
    ASSERT_TRUE(bitset.find_lowest(2, bitset.size()) == 94);

    // 0b11..11
    bitset.fill(0, bitset.size());
    ASSERT_TRUE(bitset.find_lowest(0, bitset.size()) == 0);
    ASSERT_TRUE(bitset.find_lowest(5, bitset.size()) == 5);
  }
  {
    bounded_bitset<100, reversed> bitset(95);

    // 0b0...0
    ASSERT_TRUE(bitset.find_lowest() == -1);

    // 0b1000...
    bitset.set(94);
    ASSERT_TRUE(bitset.find_lowest() == 94);

    // 0b1000...010
    bitset.set(1);
    ASSERT_TRUE(bitset.find_lowest() == 1);

    // 0b11..11
    bitset.fill(0, bitset.size());
    ASSERT_TRUE(bitset.find_lowest() == 0);
  }
  {
    bounded_bitset<100, reversed> bitset(95);

    // 0b0...0
    ASSERT_TRUE(bitset.find_highest() == -1);

    // 0b1000...
    bitset.set(94);
    ASSERT_EQ(bitset.find_highest(), 94);

    // 0b1000...010
    bitset.set(1);
    ASSERT_EQ(bitset.find_highest(), 94);

    // 0b11..11
    bitset.fill(0, bitset.size());
    ASSERT_EQ(bitset.find_highest(), 94);
  }
}

TEST(BoundedBitset, bitset_find)
{
  test_bitset_find<false>();
  test_bitset_find<true>();
}

TEST(BoundedBitset, is_contiguous)
{
  // Test contiguous condition 1. No bit set.
  {
    ASSERT_TRUE(bounded_bitset<10>({0, 0, 0, 0}).is_contiguous());
  }
  // Test contiguous condition 2. One bit set.
  {
    ASSERT_TRUE(bounded_bitset<10>({1, 0, 0, 0}).is_contiguous());
    ASSERT_TRUE(bounded_bitset<10>({0, 0, 1, 0}).is_contiguous());
    ASSERT_TRUE(bounded_bitset<10>({0, 1, 0, 0}).is_contiguous());
    ASSERT_TRUE(bounded_bitset<10>({0, 0, 0, 1}).is_contiguous());
  }
  // Test contiguous condition 3. All set bits are contiguous.
  {
    ASSERT_TRUE(bounded_bitset<10>({1, 1, 0, 0}).is_contiguous());
    ASSERT_TRUE(bounded_bitset<10>({1, 1, 1, 0}).is_contiguous());
    ASSERT_TRUE(bounded_bitset<10>({1, 1, 1, 1}).is_contiguous());
    ASSERT_TRUE(bounded_bitset<10>({0, 1, 1, 1}).is_contiguous());
    ASSERT_TRUE(bounded_bitset<10>({0, 0, 1, 1}).is_contiguous());
    ASSERT_TRUE(bounded_bitset<10>({0, 1, 1, 0}).is_contiguous());
  }
  // Not contiguous.
  {
    ASSERT_FALSE(bounded_bitset<10>({1, 0, 1, 1}).is_contiguous());
    ASSERT_FALSE(bounded_bitset<10>({1, 1, 0, 1}).is_contiguous());
    ASSERT_FALSE(bounded_bitset<10>({1, 0, 1, 1}).is_contiguous());
    ASSERT_FALSE(bounded_bitset<10>({1, 1, 0, 1}).is_contiguous());
    ASSERT_FALSE(bounded_bitset<10>({1, 0, 0, 1}).is_contiguous());
  }
}

TEST(BoundedBitset, push_back)
{
  {
    bounded_bitset<10> bitset;
    bitset.push_back(1);
    bitset.push_back(0);
    bitset.push_back(1);
    bitset.push_back(1);
    ASSERT_EQ(bitset, bounded_bitset<10>({1, 0, 1, 1}));
  }
  {
    bounded_bitset<10> bitset;
    bitset.push_back(0xbU, 4);
    ASSERT_EQ(bitset, bounded_bitset<10>({1, 0, 1, 1}));
  }
}

TEST(BoundedBitset, fold_and_accumulate)
{
  size_t fold_size = 20;

  bounded_bitset<105> big_bitmap(100);
  for (size_t i = 0; i < big_bitmap.size(); i += fold_size + 1) {
    big_bitmap.set(i);
  }

  bounded_bitset<6> fold_bitset = fold_and_accumulate<6>(big_bitmap, fold_size);
  ASSERT_EQ(big_bitmap.size() / fold_size, fold_bitset.count());
  ASSERT_EQ(fold_bitset.count(), big_bitmap.count());
  ASSERT_TRUE(fold_bitset.is_contiguous());
  ASSERT_EQ(0, fold_bitset.find_lowest());
}

TEST(BoundedBitset, for_each)
{
  bounded_bitset<10>  mask   = {false, true, false, true, false, true, false, true, false, true};
  std::array<int, 10> values = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  std::vector<int>    output;

  mask.for_each(0, mask.size(), [&output, &values](int n) { output.emplace_back(values[n]); });
  ASSERT_EQ(output, std::vector<int>({2, 4, 6, 8, 10}));

  output.resize(0);
  mask.for_each(
      0, mask.size(), [&output, &values](int n) { output.emplace_back(values[n]); }, false);
  ASSERT_EQ(output, std::vector<int>({1, 3, 5, 7, 9}));

  output.resize(0);
  mask.for_each(2, mask.size(), [&output, &values](int n) { output.emplace_back(values[n]); });
  ASSERT_EQ(output, std::vector<int>({4, 6, 8, 10}));

  output.resize(0);
  mask.for_each(0, 9, [&output, &values](int n) { output.emplace_back(values[n]); });
  ASSERT_EQ(output, std::vector<int>({2, 4, 6, 8}));
}
