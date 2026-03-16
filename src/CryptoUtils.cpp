// For open-source license, please refer to
// [License](https://github.com/HikariObfuscator/Hikari/wiki/License).
//===----------------------------------------------------------------------===//
#include "CryptoUtils.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"
#include <chrono>
#include <ctime>
#include <random>

using namespace llvm;

namespace ni_pass {

ManagedStatic<CryptoUtils> cryptoutils;

CryptoUtils::CryptoUtils() {
  eng = new std::mt19937_64();
  prng_seed();
  }

CryptoUtils::~CryptoUtils() {
  if (eng) {
    delete eng;
    eng = nullptr;
  }
}

void CryptoUtils::prng_seed() {
  std::random_device rd;
  std::mt19937_64 rng(rd());
  std::uniform_int_distribution<std::uint_fast64_t> dist;
  prng_seed(dist(rng));
}

void CryptoUtils::prng_seed(std::uint_fast64_t seed) {
  eng->seed(seed);
}

std::uint_fast64_t CryptoUtils::get_raw() {
  return eng->operator()();
}

uint32_t CryptoUtils::get_range(uint32_t min, uint32_t max) {
  std::uniform_int_distribution<uint32_t> dist(min, max - 1);
  return dist(*eng);
}

uint32_t CryptoUtils::scramble32(
    uint32_t in, std::unordered_map<uint32_t, uint32_t> &VMap) {
  if (VMap.count(in)) {
    return VMap[in];
  }
  uint32_t v = get_uint32_t();
  VMap[in] = v;
  return v;
}

} // namespace ni_pass
