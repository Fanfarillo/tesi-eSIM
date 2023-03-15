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

#include "srsran/adt/byte_buffer.h"
#include "srsran/support/test_utils.h"
#include <gtest/gtest.h>
#include <list>
#include <random>

using namespace srsran;

static_assert(std::is_same<byte_buffer::value_type, uint8_t>::value, "Invalid valid_type");
static_assert(std::is_same<byte_buffer_view::value_type, uint8_t>::value, "Invalid valid_type");
static_assert(std::is_same<byte_buffer::iterator::value_type, uint8_t>::value, "Invalid valid_type");
static_assert(std::is_same<byte_buffer::const_iterator::value_type, uint8_t>::value, "Invalid valid_type");
static_assert(std::is_same<byte_buffer::iterator::reference, uint8_t&>::value, "Invalid reference type");
static_assert(std::is_same<byte_buffer::const_iterator::reference, const uint8_t&>::value, "Invalid reference type");
static_assert(std::is_same<byte_buffer::const_iterator::pointer, const uint8_t*>::value, "Invalid pointer type");
static_assert(is_byte_buffer_range<byte_buffer>::value, "Invalid metafunction is_byte_buffer_range");
static_assert(is_byte_buffer_range<byte_buffer_view>::value, "Invalid metafunction is_byte_buffer_range");
static_assert(is_byte_buffer_range<byte_buffer_slice>::value, "Invalid metafunction is_byte_buffer_range");

const size_t  small_vec_size = 6;
const size_t  large_vec_size = byte_buffer_segment::SEGMENT_SIZE * 4;
static size_t random_vec_size(unsigned lb = 1, unsigned ub = large_vec_size)
{
  return test_rgen::uniform_int<unsigned>(lb, ub);
}

/// Creates a vector with size randomly generated within defined bounds.
static std::vector<uint8_t> make_vec(unsigned lb = 1, unsigned ub = byte_buffer_segment::SEGMENT_SIZE * 4)
{
  return test_rgen::random_vector<uint8_t>(test_rgen::uniform_int<unsigned>(lb, ub));
}

/// Creates a small vector of bytes that fits in one segment.
static std::vector<uint8_t> make_small_vec()
{
  return make_vec(6, 6);
}

/// Creates a large vector of bytes that fills a segment TAILROOM.
static std::vector<uint8_t> make_large_vec()
{
  size_t sz = byte_buffer_segment::capacity() - byte_buffer_segment::DEFAULT_HEADROOM;
  return make_vec(sz, sz);
}

static std::vector<uint8_t> concat_vec(span<const uint8_t> before, span<const uint8_t> after)
{
  std::vector<uint8_t> ret(before.size() + after.size());
  std::copy(before.begin(), before.end(), ret.begin());
  std::copy(after.begin(), after.end(), ret.begin() + before.size());
  return ret;
}

// Performs several checks that ensure the valid state of the byte_buffer length.
// Note1: the byte_buffer::iterator operator- sums the lengths of the byte_buffer individual segments.
// Note2: std::distance counts the number of iterations between begin() and end().
#define ASSERT_EQ_LEN(buffer, len)                                                                                     \
  ASSERT_EQ(buffer.empty(), (len) == 0);                                                                               \
  ASSERT_EQ(buffer.length(), (len));                                                                                   \
  ASSERT_EQ(buffer.end() - buffer.begin(), (len));                                                                     \
  ASSERT_EQ(std::distance(buffer.begin(), buffer.end()), (len));

// Ensures commutativity of byte_buffer::operator==, and consistency when compared to std::equal(...).
#define ASSERT_EQ_BUFFER(buffer1, buffer2)                                                                             \
  ASSERT_EQ(buffer1, buffer2);                                                                                         \
  std::equal(buffer1.begin(), buffer1.end(), buffer2.begin(), buffer2.end());                                          \
  ASSERT_EQ(buffer2, buffer1)

///////////////////////// byte_buffer_test //////////////////////////////

class one_vec_size_param : public ::testing::TestWithParam<size_t>
{
protected:
  size_t               sz1   = GetParam();
  std::vector<uint8_t> bytes = test_rgen::random_vector<uint8_t>(sz1);
};

class two_vec_sizes_param : public ::testing::TestWithParam<std::tuple<size_t, size_t>>
{
protected:
  size_t               sz1    = std::get<0>(GetParam());
  size_t               sz2    = std::get<1>(GetParam());
  std::vector<uint8_t> bytes1 = test_rgen::random_vector<uint8_t>(sz1);
  std::vector<uint8_t> bytes2 = test_rgen::random_vector<uint8_t>(sz2);
};

class three_vec_sizes_param : public ::testing::TestWithParam<std::tuple<size_t, size_t, size_t>>
{
protected:
  size_t               sz1    = std::get<0>(GetParam());
  size_t               sz2    = std::get<1>(GetParam());
  size_t               sz3    = std::get<2>(GetParam());
  std::vector<uint8_t> bytes1 = test_rgen::random_vector<uint8_t>(sz1);
  std::vector<uint8_t> bytes2 = test_rgen::random_vector<uint8_t>(sz2);
  std::vector<uint8_t> bytes3 = test_rgen::random_vector<uint8_t>(sz3);
};

TEST(byte_buffer_test, empty_byte_buffer_in_valid_state)
{
  byte_buffer pdu;
  ASSERT_EQ_LEN(pdu, 0);
  ASSERT_EQ(pdu, std::vector<uint8_t>{});
  ASSERT_EQ(pdu, std::list<uint8_t>{});
}

TEST_P(one_vec_size_param, ctor_with_span)
{
  byte_buffer pdu{this->bytes};

  ASSERT_EQ_LEN(pdu, bytes.size());
  ASSERT_TRUE(std::equal(pdu.begin(), pdu.end(), bytes.begin(), bytes.end()));
}

TEST_P(one_vec_size_param, equality_comparison)
{
  byte_buffer        pdu{this->bytes};
  byte_buffer        pdu2{bytes};
  std::list<uint8_t> not_a_span{bytes.begin(), bytes.end()};

  // comparison byte_buffer vs span.
  ASSERT_EQ_BUFFER(pdu, bytes);

  // comparison byte_buffer vs byte_buffer.
  ASSERT_EQ_BUFFER(pdu, pdu2);

  // comparison byte_buffer vs any other range type.
  ASSERT_EQ(pdu, not_a_span);

  // comparison byte_buffer vs other range of larger length.
  std::vector<uint8_t> larger_bytes = concat_vec(bytes, make_vec());
  std::list<uint8_t>   larger_not_a_span{larger_bytes.begin(), larger_bytes.end()};
  pdu2 = byte_buffer{larger_bytes};
  ASSERT_NE(pdu, larger_bytes);
  ASSERT_NE(larger_bytes, pdu);
  ASSERT_NE(pdu, pdu2);
  ASSERT_NE(pdu2, pdu);
  ASSERT_NE(pdu, larger_not_a_span);

  // comparison byte_buffer vs other range of shorter length.
  std::vector<uint8_t> shorter_bytes(bytes.begin(),
                                     bytes.begin() + test_rgen::uniform_int<unsigned>(0, bytes.size() - 1));
  std::list<uint8_t>   shorter_not_a_span{shorter_bytes.begin(), shorter_bytes.end()};
  pdu2 = byte_buffer{shorter_bytes};
  ASSERT_NE(pdu, shorter_bytes);
  ASSERT_NE(shorter_bytes, pdu);
  ASSERT_NE(pdu, pdu2);
  ASSERT_NE(pdu2, pdu);
  ASSERT_NE(pdu, shorter_not_a_span);

  // comparison of byte_buffer vs other range of equal length but different content.
  std::vector<uint8_t> neq_bytes = bytes;
  neq_bytes[test_rgen::uniform_int<unsigned>(0, neq_bytes.size() - 1)]++;
  std::list<uint8_t> neq_not_a_span{neq_bytes.begin(), neq_bytes.end()};
  ASSERT_NE(pdu, neq_bytes);
  ASSERT_NE(neq_bytes, pdu);
  ASSERT_NE(pdu, pdu2);
  ASSERT_NE(pdu2, pdu);
  ASSERT_NE(pdu, neq_not_a_span);
}

TEST_P(one_vec_size_param, move_ctor)
{
  byte_buffer pdu;
  pdu.append(this->bytes);

  byte_buffer pdu2{std::move(pdu)};
  ASSERT_TRUE(pdu.empty());
  ASSERT_FALSE(pdu2.empty());
  ASSERT_EQ_BUFFER(pdu2, bytes);
}

TEST(byte_buffer, initializer_list)
{
  byte_buffer          pdu = {1, 2, 3, 4, 5, 6};
  std::vector<uint8_t> bytes{1, 2, 3, 4, 5, 6};

  ASSERT_EQ_LEN(pdu, 6);
  ASSERT_TRUE(std::equal(pdu.begin(), pdu.end(), bytes.begin(), bytes.end()));
}

TEST_P(two_vec_sizes_param, append)
{
  byte_buffer pdu;

  // Append span of bytes (that may occupy more than one segment).
  pdu.append(this->bytes1);
  ASSERT_EQ_LEN(pdu, bytes1.size());
  ASSERT_EQ_BUFFER(pdu, bytes1);

  // Append two byte_buffers.
  byte_buffer pdu2{bytes2};
  ASSERT_EQ(pdu2, bytes2);
  pdu2.append(pdu);
  ASSERT_EQ(pdu.length() + bytes2.size(), pdu2.length());
  ASSERT_EQ(pdu2.length(), pdu2.end() - pdu2.begin());
  ASSERT_EQ(pdu2, concat_vec(bytes2, bytes1));
}

TEST_P(two_vec_sizes_param, prepend)
{
  byte_buffer pdu;

  // prepend in empty byte_buffer.
  pdu.prepend(bytes1);
  ASSERT_EQ(pdu.length(), bytes1.size());
  ASSERT_EQ(pdu, bytes1);

  // prepend in non-empty byte_buffer.
  pdu.prepend(bytes2);
  ASSERT_EQ(pdu.length(), bytes1.size() + bytes2.size());
  ASSERT_EQ(pdu, concat_vec(bytes2, bytes1));
}

TEST_P(one_vec_size_param, clear)
{
  byte_buffer pdu;
  pdu.append(this->bytes);

  ASSERT_TRUE(not pdu.empty());
  pdu.clear();
  ASSERT_EQ_LEN(pdu, 0);

  // multiple clear calls are valid.
  pdu.clear();
  ASSERT_TRUE(pdu.empty());
}

TEST(byte_buffer, iterator)
{
  byte_buffer pdu;

  std::vector<uint8_t> bytes = make_small_vec();
  pdu.append(bytes);

  // iterator
  size_t i = 0;
  for (byte_buffer::iterator it = pdu.begin(); it != pdu.end(); ++it, ++i) {
    TESTASSERT_EQ(bytes[i], *it);
  }
  TESTASSERT_EQ(bytes.size(), i);

  // const iterator
  i = 0;
  for (byte_buffer::const_iterator it = pdu.cbegin(); it != pdu.cend(); ++it, ++i) {
    TESTASSERT_EQ(bytes[i], *it);
  }
  TESTASSERT_EQ(bytes.size(), i);

  // distance
  TESTASSERT_EQ(bytes.size(), pdu.length());
  TESTASSERT_EQ(bytes.size(), (size_t)(pdu.end() - pdu.begin()));
  TESTASSERT_EQ(bytes.size() - 2, (size_t)(pdu.end() - (pdu.begin() + 2)));

  // multiple segments
  std::vector<uint8_t> bytes2 = make_large_vec();
  pdu.append(bytes2);
  std::vector<uint8_t> bytes_concat = concat_vec(bytes, bytes2);

  // iterator
  i = 0;
  for (byte_buffer::iterator it = pdu.begin(); it != pdu.end(); ++it, ++i) {
    TESTASSERT_EQ(bytes_concat[i], *it);
  }
  TESTASSERT_EQ(bytes_concat.size(), i);

  // const iterator
  i = 0;
  for (byte_buffer::const_iterator it = pdu.cbegin(); it != pdu.cend(); ++it, ++i) {
    TESTASSERT_EQ(bytes_concat[i], *it);
  }
  TESTASSERT_EQ(bytes_concat.size(), i);

  // distance
  TESTASSERT_EQ(bytes_concat.size(), pdu.length());
  TESTASSERT_EQ(bytes_concat.size(), (size_t)(pdu.end() - pdu.begin()));
  TESTASSERT_EQ(bytes_concat.size() - 2, (size_t)(pdu.end() - (pdu.begin() + 2)));
}

TEST(byte_buffer_test, deep_copy_works_for_empty_byte_buffer)
{
  byte_buffer pdu;
  byte_buffer pdu2;
  pdu2 = pdu.deep_copy();
  ASSERT_TRUE(pdu.empty());
  ASSERT_TRUE(pdu.empty());
}

TEST_P(two_vec_sizes_param, deep_copy)
{
  byte_buffer pdu;
  pdu.append(bytes1);
  auto bytes_concat = concat_vec(bytes1, bytes2);

  // Deep copy.
  byte_buffer pdu2;
  pdu2 = pdu.deep_copy();
  ASSERT_FALSE(pdu.empty());
  ASSERT_FALSE(pdu2.empty());
  ASSERT_EQ_BUFFER(pdu, pdu2);
  ASSERT_EQ_BUFFER(pdu2, bytes1);

  pdu2.append(bytes2);
  ASSERT_EQ_BUFFER(pdu, bytes1);
  ASSERT_NE(pdu, pdu2);
  ASSERT_EQ_BUFFER(pdu2, bytes_concat);
}

TEST_P(two_vec_sizes_param, shallow_copy_and_append)
{
  byte_buffer pdu;
  pdu.append(bytes1);

  {
    byte_buffer pdu2 = pdu.copy();
    ASSERT_EQ_BUFFER(pdu2, pdu);
    ASSERT_EQ_BUFFER(pdu2, bytes1);
    pdu2.append(bytes2);
    ASSERT_EQ(pdu2, pdu);
    ASSERT_EQ(pdu.length(), pdu.end() - pdu.begin()) << "shallow copied-from byte_buffer::length() got corrupted";
    ASSERT_EQ(pdu2.length(), pdu2.end() - pdu2.begin()) << "shallow copy byte_buffer::length() got corrupted";
  }
  ASSERT_EQ_BUFFER(pdu, concat_vec(bytes1, bytes2));
  ASSERT_EQ(pdu.length(), pdu.end() - pdu.begin());
}

TEST_P(three_vec_sizes_param, shallow_copy_prepend_and_append)
{
  byte_buffer pdu;
  pdu.append(bytes1);

  {
    byte_buffer pdu2 = pdu.copy();
    ASSERT_EQ_BUFFER(pdu2, pdu);
    ASSERT_EQ_BUFFER(pdu2, bytes1);
    pdu2.prepend(bytes2);
    ASSERT_EQ(pdu2, pdu);
    pdu2.append(bytes3);
    ASSERT_EQ(pdu2, pdu);
    ASSERT_EQ(pdu.length(), pdu.end() - pdu.begin()) << "shallow copied-from byte_buffer::length() got corrupted";
    ASSERT_EQ(pdu2.length(), pdu2.end() - pdu2.begin()) << "shallow copy byte_buffer::length() got corrupted";
  }
  ASSERT_EQ_BUFFER(pdu, concat_vec(bytes2, concat_vec(bytes1, bytes3)));
  ASSERT_EQ(pdu.length(), pdu.end() - pdu.begin());
}

TEST(byte_buffer, formatter)
{
  byte_buffer          pdu;
  std::vector<uint8_t> bytes = {1, 2, 3, 4, 15, 16, 255};
  pdu.append(bytes);

  fmt::print("PDU: {}\n", pdu);
  std::string result = fmt::format("{}", pdu);
  ASSERT_EQ(result, "01 02 03 04 0f 10 ff");
}

TEST(byte_buffer, trim)
{
  byte_buffer          pdu;
  std::vector<uint8_t> bytes = make_small_vec();
  pdu.append(bytes);

  TESTASSERT(pdu == bytes);
  pdu.trim_head(2);
  TESTASSERT(pdu == span<const uint8_t>{bytes}.subspan(2, bytes.size() - 2));

  std::vector<uint8_t> bytes2 = make_large_vec();
  pdu.append(bytes2);

  auto bytes_concat = bytes;
  bytes_concat.insert(bytes_concat.end(), bytes2.begin(), bytes2.end());
  TESTASSERT(pdu == span<const uint8_t>{bytes_concat}.subspan(2, bytes_concat.size() - 2));

  pdu.trim_head(bytes.size() - 2);
  TESTASSERT(pdu == bytes2);

  // should make the first segment empty and remove it.
  pdu.trim_head(bytes2.size() - 2);
  TESTASSERT(pdu == span<const uint8_t>{bytes2}.last(2));
}

TEST(byte_buffer, prepend_and_trim_tail)
{
  byte_buffer        pdu;
  byte_buffer        sdu;
  uint32_t           pdu_len    = byte_buffer_segment::SEGMENT_SIZE - 5 + test_rgen::uniform_int<unsigned>(0, 10);
  constexpr uint32_t trim_len   = 4;
  constexpr uint32_t prefix_len = 3;
  for (uint32_t i = 0; i < pdu_len; i++) {
    pdu.append(i);
  }

  sdu.append(pdu.begin() + prefix_len, pdu.end());
  std::array<uint8_t, prefix_len> hdr_buf;
  std::copy(pdu.begin(), pdu.begin() + prefix_len, hdr_buf.begin());
  sdu.prepend(hdr_buf);

  ASSERT_EQ(sdu.length(), pdu_len);
  ASSERT_EQ(std::distance(sdu.begin(), sdu.end()), pdu_len);

  sdu.trim_tail(trim_len);
  ASSERT_EQ_LEN(sdu, pdu_len - trim_len);
}

TEST_P(three_vec_sizes_param, shallow_copy_prepend_and_append_keeps_validity)
{
  // When a byte_buffer::prepend causes the byte_buffer head segment to move, any previously existing shallow copies
  // could become invalidated. To avoid this issue, we perform COW on prepend, when more than one byte_buffer points to
  // the same head segment.
  byte_buffer pdu{bytes1};

  byte_buffer pdu2{pdu.copy()};
  pdu.prepend(bytes2);
  pdu.append(bytes3);

  ASSERT_EQ(pdu, concat_vec(concat_vec(bytes2, bytes1), bytes3));
  ASSERT_EQ(pdu2.length(), pdu2.end() - pdu2.begin()) << "shallow copied-from byte_buffer::length() got corrupted";
}

TEST_P(three_vec_sizes_param, shallow_copy_reserve_prepend_and_append_keeps_validity)
{
  // When a byte_buffer::prepend causes the byte_buffer head segment to move, any previously existing shallow copies
  // could become invalidated. To avoid this issue, we perform COW on prepend, when more than one byte_buffer points to
  // the same head segment.
  byte_buffer pdu{bytes1};

  byte_buffer      pdu2{pdu.copy()};
  byte_buffer_view v = pdu.reserve_prepend(bytes2.size());
  pdu.append(bytes3);
  std::copy(bytes2.begin(), bytes2.end(), v.begin());

  ASSERT_EQ(pdu, concat_vec(concat_vec(bytes2, bytes1), bytes3));
  ASSERT_EQ(pdu2.length(), pdu2.end() - pdu2.begin()) << "shallow copied-from byte_buffer::length() got corrupted";
}

TEST(byte_buffer, is_contiguous)
{
  byte_buffer          pdu;
  std::vector<uint8_t> bytes        = make_small_vec();
  std::vector<uint8_t> bytes2       = make_large_vec();
  auto                 bytes_concat = concat_vec(bytes, bytes2);

  pdu.append(bytes);
  ASSERT_TRUE(pdu.is_contiguous());
  pdu.append(bytes2);
  ASSERT_TRUE(not pdu.is_contiguous());

  ASSERT_EQ_BUFFER(pdu, bytes_concat);
  ASSERT_TRUE(pdu.linearize() < 0);
  ASSERT_EQ_BUFFER(pdu, bytes_concat) << "A failed linearization should not alter the original byte_buffer";

  pdu.trim_tail(bytes.size() - 1);
  ASSERT_TRUE(not pdu.is_contiguous());
  ASSERT_TRUE(pdu.linearize() < 0);

  pdu.trim_tail(1);
  ASSERT_TRUE(pdu.is_contiguous());
}

TEST(byte_buffer, hexdump)
{
  std::vector<uint8_t> bytes{0x1, 0x2, 0x3, 0x4, 0x5, 0xff};
  byte_buffer          pdu = make_byte_buffer("0102030405FF");
  TESTASSERT(pdu == bytes);
}

TEST(byte_buffer, copy_to_span)
{
  byte_buffer          pdu;
  std::vector<uint8_t> bytes        = make_small_vec();
  std::vector<uint8_t> bytes2       = make_large_vec();
  auto                 bytes_concat = concat_vec(bytes, bytes2);

  std::vector<uint8_t> dst_vec(bytes_concat.size(), 0xfe);
  dst_vec.reserve(bytes_concat.size());
  span<uint8_t> dst_span = {dst_vec};
  size_t        len      = 0;

  // test copy of empty buffer
  len = copy_segments(pdu, dst_span);
  ASSERT_EQ(len, pdu.length());
  ASSERT_TRUE(std::equal(pdu.begin(), pdu.end(), dst_span.begin()));
  ASSERT_EQ(dst_span.data()[len], 0xfe);

  // test copy of small buffer
  pdu.append(bytes);
  len = copy_segments(pdu, dst_span);
  ASSERT_EQ(len, pdu.length());
  ASSERT_TRUE(std::equal(pdu.begin(), pdu.end(), dst_span.begin()));
  ASSERT_EQ(dst_span.data()[len], 0xfe);

  // test copy of large buffer
  pdu.append(bytes2);
  len = copy_segments(pdu, dst_span);
  ASSERT_EQ(len, pdu.length());
  ASSERT_EQ(dst_span, pdu);

  // test copy to short span
  std::fill(dst_span.begin(), dst_span.end(), 0xfe);
  ASSERT_EQ(dst_span.back(), 0xfe);
  span<uint8_t> dst_subspan = dst_span.subspan(0, pdu.length() - 1);
  len                       = copy_segments(pdu, dst_subspan);
  ASSERT_EQ(len, pdu.length() - 1);
  ASSERT_TRUE(std::equal(dst_subspan.begin(), dst_subspan.end(), pdu.begin()));
  ASSERT_EQ(dst_span.data()[len], 0xfe);

  // test copy to very short span
  std::fill(dst_span.begin(), dst_span.end(), 0xfe);
  dst_subspan = dst_span.subspan(0, 1);
  len         = copy_segments(pdu, dst_subspan);
  ASSERT_EQ(len, 1);
  ASSERT_TRUE(std::equal(dst_subspan.begin(), dst_subspan.end(), pdu.begin()));
  ASSERT_EQ(dst_span.data()[len], 0xfe);
}

TEST(byte_buffer, copy_to_iterator)
{
  byte_buffer          pdu;
  std::vector<uint8_t> bytes        = make_small_vec();
  std::vector<uint8_t> bytes2       = make_large_vec();
  auto                 bytes_concat = concat_vec(bytes, bytes2);

  std::vector<uint8_t> dst_vec(bytes_concat.size(), 0);
  dst_vec.reserve(bytes_concat.size());
  span<uint8_t> dst_span = {dst_vec};

  // test copy of empty buffer
  span<uint8_t> dst_subspan = dst_span.subspan(0, pdu.length());
  copy_segments(pdu, dst_subspan.begin());
  ASSERT_EQ(pdu, dst_subspan);

  // test copy of small buffer
  pdu.append(bytes);
  dst_subspan = dst_span.subspan(0, pdu.length());
  copy_segments(pdu, dst_subspan.begin());
  ASSERT_EQ(pdu, dst_subspan);

  // test copy of large buffer
  pdu.append(bytes2);
  dst_subspan = dst_span.subspan(0, pdu.length());
  copy_segments(pdu, dst_subspan.begin());
  ASSERT_EQ(pdu, dst_subspan);
}

TEST(byte_buffer, to_span)
{
  byte_buffer          pdu;
  std::vector<uint8_t> bytes        = make_small_vec();
  std::vector<uint8_t> bytes2       = make_large_vec();
  auto                 bytes_concat = concat_vec(bytes, bytes2);

  std::vector<uint8_t> tmp_mem(bytes_concat.size(), 0);
  tmp_mem.reserve(bytes_concat.size());

  // test view of empty buffer
  span<const uint8_t> dst = to_span(pdu, tmp_mem);
  ASSERT_TRUE(dst.empty());
  ASSERT_EQ(dst, pdu);

  // test view of small buffer (no copy)
  pdu.append(bytes);
  dst = to_span(pdu, tmp_mem);
  ASSERT_EQ(pdu, dst);
  ASSERT_EQ(dst, span<const uint8_t>{*pdu.segments().begin()});

  // test copy of large buffer (with copy)
  pdu.append(bytes2);
  dst = to_span(pdu, tmp_mem);
  ASSERT_EQ(pdu, dst);
  ASSERT_EQ(dst, span<const uint8_t>{tmp_mem});
}

TEST(byte_buffer, iterator_plus_equal_op)
{
  // Test with small vector of bytes
  // Make initial vector
  byte_buffer          pdu;
  std::vector<uint8_t> bytes = make_small_vec();
  pdu.append(bytes);

  auto it = pdu.begin();
  TESTASSERT(it != pdu.cend());

  // Point reader at 1 byte before the end
  it += (pdu.length() - 1);
  TESTASSERT(it != pdu.cend());

  // Point reader at the end
  it = pdu.begin();
  it += pdu.length();
  TESTASSERT(it == pdu.cend());

  // Test with big vector of bytes
  bytes = make_large_vec();
  pdu.clear();
  pdu.append(bytes);

  it = pdu.begin();
  TESTASSERT(it != pdu.cend());

  // Point reader at 1 byte before the end
  it += (pdu.length() - 1);
  TESTASSERT(pdu.cend() != it);

  // Point reader at the end
  it = pdu.begin();
  it += pdu.length();
  TESTASSERT(it == pdu.cend());

  // Test with byte buffer made of several segments
  pdu.append(bytes);
  pdu.append(bytes);

  it = pdu.begin();
  TESTASSERT(pdu.cend() != it);

  // Point reader at 1 byte before the end
  it += (pdu.length() - 1);
  TESTASSERT(it != pdu.cend());

  // Point reader at the end
  it = pdu.begin();
  it += pdu.length();
  TESTASSERT(it == pdu.cend());
}

TEST(byte_buffer, iterator_of_segments)
{
  byte_buffer          pdu;
  std::vector<uint8_t> small_vec_bytes = make_small_vec();

  // empty buffer.
  ASSERT_EQ(pdu.segments().begin(), pdu.segments().end());

  // one-segment buffer
  pdu.append(small_vec_bytes);
  ASSERT_NE(pdu.segments().begin(), pdu.segments().end());
  ASSERT_EQ(*pdu.segments().begin(), span<uint8_t>(small_vec_bytes));
  ASSERT_EQ(++pdu.segments().begin(), pdu.segments().end());

  // multiple-segment buffer.
  pdu.append(make_vec(1, 10000));
  std::vector<uint8_t> total_bytes(pdu.begin(), pdu.end());
  unsigned             seg_offset = 0;
  for (auto seg_it = pdu.segments().begin(); seg_it != pdu.segments().end(); ++seg_it) {
    ASSERT_TRUE(seg_it->size() > 0);
    ASSERT_EQ(*seg_it, span<uint8_t>(total_bytes.data() + seg_offset, seg_it->size()));
    seg_offset += seg_it->size();
  }
  ASSERT_EQ(seg_offset, total_bytes.size());
}

TEST(byte_buffer_view, length)
{
  byte_buffer          pdu;
  unsigned             len   = test_rgen::uniform_int<unsigned>(1, 100000);
  std::vector<uint8_t> bytes = make_vec(len, len);
  pdu.append(bytes);

  byte_buffer_view view = pdu;

  ASSERT_FALSE(view.empty());
  ASSERT_EQ(len, view.length());
  ASSERT_EQ(len, view.end() - view.begin());
  unsigned offset = test_rgen::uniform_int<unsigned>(0, len);
  unsigned len2   = test_rgen::uniform_int<unsigned>(1, len - offset);
  ASSERT_EQ(len2, view.view(offset, len2).length());
}

TEST(byte_buffer_view, segment_iterator)
{
  byte_buffer          pdu;
  std::vector<uint8_t> bytes = make_vec();
  pdu.append(bytes);

  unsigned         offset      = test_rgen::uniform_int<unsigned>(0, bytes.size() - 1);
  unsigned         last_offset = test_rgen::uniform_int<unsigned>(offset + 1, bytes.size());
  byte_buffer_view view{pdu.begin() + offset, pdu.begin() + last_offset};

  unsigned seg_offset = offset;
  for (auto seg_it = view.segments().begin(); seg_it != view.segments().end(); ++seg_it) {
    ASSERT_NE(seg_it, view.segments().end());
    unsigned seg_len = seg_it->size();
    ASSERT_GT(seg_len, 0);
    ASSERT_EQ(*seg_it, span<const uint8_t>(bytes.data() + seg_offset, seg_len));
    seg_offset += seg_len;
  }
  ASSERT_EQ(seg_offset, last_offset);
}

TEST(byte_buffer_reader, split_advance)
{
  // Test with small vector of bytes
  // Make initial vector
  byte_buffer          pdu;
  std::vector<uint8_t> bytes = make_small_vec();
  pdu.append(bytes);

  auto it = pdu.begin();
  TESTASSERT(it != pdu.cend());

  // Get reader and check that beginning and end coincide with the original
  byte_buffer_reader pdu_reader{byte_buffer_view{pdu}};
  TESTASSERT(pdu_reader.begin() == pdu.begin());
  TESTASSERT(pdu_reader.end() == pdu.end());

  // Stop reader at 1 byte to the end
  auto view = pdu_reader.split_and_advance(pdu.length() - 1);
  TESTASSERT(pdu_reader.begin() != pdu_reader.end());
  TESTASSERT(pdu_reader.end() == pdu.end());
  TESTASSERT(view.begin() == pdu.begin());
  TESTASSERT(view.end() == pdu_reader.begin());

  // Move reader 1 byte ahead, to the end
  view = pdu_reader.split_and_advance(1);
  TESTASSERT(pdu_reader.begin() == pdu_reader.end());
  TESTASSERT(view.end() == pdu_reader.begin());

  // Test with byte buffer made of several segments
  // Make initial vector
  bytes = make_large_vec();
  pdu.clear();
  pdu.append(bytes);
  pdu.append(bytes);
  pdu.append(bytes);

  it = pdu.begin();
  TESTASSERT(it != pdu.cend());

  // Get reader and check that beginning and end coincide with the original
  byte_buffer_reader pdu_long_reader{byte_buffer_view{pdu}};
  TESTASSERT(pdu_long_reader.begin() == pdu.begin());
  TESTASSERT(pdu_long_reader.end() == pdu.end());

  // Stop reader at 1 byte to the end
  view = pdu_long_reader.split_and_advance(pdu.length() - 1);
  TESTASSERT(pdu_long_reader.begin() != pdu_long_reader.end());
  TESTASSERT(pdu_long_reader.end() == pdu.end());
  TESTASSERT(view.begin() == pdu.begin());
  TESTASSERT(view.end() == pdu_long_reader.begin());

  // Move reader 1 byte ahead, to the end
  view = pdu_long_reader.split_and_advance(1);
  TESTASSERT(pdu_long_reader.begin() == pdu_long_reader.end());
  TESTASSERT(view.end() == pdu_long_reader.begin());
}

TEST(byte_buffer_writer, all)
{
  byte_buffer        pdu;
  byte_buffer_writer writer{pdu};

  TESTASSERT(pdu.empty());
  TESTASSERT(writer.empty());

  writer.append(5);
  TESTASSERT(not pdu.empty());
  TESTASSERT(not writer.empty());
  TESTASSERT_EQ(1, pdu.length());
  TESTASSERT_EQ(1, writer.length());

  writer.append({0, 1, 2, 3, 4});
  TESTASSERT_EQ(6, pdu.length());
  TESTASSERT_EQ(6, writer.length());
  bool is_eq = pdu == std::vector<uint8_t>{5, 0, 1, 2, 3, 4};
  TESTASSERT(is_eq);

  TESTASSERT_EQ(4, writer.back());
  writer.back() += 6;
  TESTASSERT_EQ(10, writer.back());
}

TEST(byte_buffer, reserve_prepend)
{
  byte_buffer pdu;

  // Prepend small vector
  std::vector<uint8_t> small_vec = make_small_vec();
  byte_buffer_view     view      = pdu.reserve_prepend(small_vec.size());
  TESTASSERT_EQ(small_vec.size(), pdu.length());
  TESTASSERT_EQ(small_vec.size(), view.length());

  std::copy(small_vec.begin(), small_vec.end(), view.begin());
  TESTASSERT(pdu == small_vec);
  TESTASSERT(view == small_vec);

  // Prepend big vector
  std::vector<uint8_t> big_vec = make_large_vec();
  byte_buffer_view     view2   = pdu.reserve_prepend(big_vec.size());
  TESTASSERT_EQ(small_vec.size() + big_vec.size(), pdu.length());
  TESTASSERT_EQ(big_vec.size(), view2.length());

  std::copy(big_vec.begin(), big_vec.end(), view2.begin());
  TESTASSERT(view2 == big_vec);
}

TEST(byte_buffer_chain, all)
{
  byte_buffer pdu;
  TESTASSERT(pdu.empty());
  std::vector<uint8_t> big_vec      = make_large_vec();
  std::vector<uint8_t> small_vec    = make_small_vec();
  std::vector<uint8_t> bytes_concat = big_vec;
  bytes_concat.insert(bytes_concat.end(), small_vec.begin(), small_vec.end());
  std::vector<uint8_t> bytes_concat2 = bytes_concat;
  bytes_concat2.insert(bytes_concat2.end(), big_vec.begin(), big_vec.end());

  // Chain big vector to empty buffer
  byte_buffer pdu2(small_vec);
  TESTASSERT(pdu2 == small_vec);
  pdu.chain_before(std::move(pdu2));
  TESTASSERT(not pdu.empty());
  TESTASSERT(pdu == small_vec);
  TESTASSERT(pdu2.empty());

  // Chain byte_buffer before another non-empty byte_buffer.
  pdu2.append(big_vec);
  pdu.chain_before(std::move(pdu2));
  TESTASSERT(pdu2.empty());
  TESTASSERT_EQ(big_vec.size() + small_vec.size(), pdu.length());
  TESTASSERT(pdu == bytes_concat);

  // Chain byte_buffer after another non-empty byte_buffer.
  pdu2.append(big_vec);
  pdu.chain_after(std::move(pdu2));
  TESTASSERT(pdu2.empty());
  TESTASSERT_EQ(big_vec.size() * 2 + small_vec.size(), pdu.length());
  TESTASSERT(pdu == bytes_concat2);
}

INSTANTIATE_TEST_SUITE_P(byte_buffer_test,
                         one_vec_size_param,
                         ::testing::Values(small_vec_size, large_vec_size, random_vec_size()));

INSTANTIATE_TEST_SUITE_P(byte_buffer_test,
                         two_vec_sizes_param,
                         ::testing::Combine(::testing::Values(small_vec_size, large_vec_size, random_vec_size()),
                                            ::testing::Values(small_vec_size, large_vec_size, random_vec_size())));

INSTANTIATE_TEST_SUITE_P(byte_buffer_test,
                         three_vec_sizes_param,
                         ::testing::Combine(::testing::Values(small_vec_size, large_vec_size, random_vec_size()),
                                            ::testing::Values(small_vec_size, large_vec_size, random_vec_size()),
                                            ::testing::Values(small_vec_size, large_vec_size, random_vec_size())));
