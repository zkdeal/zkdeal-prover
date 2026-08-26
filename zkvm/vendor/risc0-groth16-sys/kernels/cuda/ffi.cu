#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>

#define FEATURE_BN254

#include "ff/alt_bn128-fp2.hpp"

#include "ec/affine_t.hpp"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wbitwise-instead-of-logical"
#include "ec/jacobian_t.hpp"
#pragma clang diagnostic pop

#include "ec/xyzz_t.hpp"

typedef Affine_t<fp_t> affine_t;
typedef jacobian_t<fp_t> point_t;
typedef xyzz_t<fp_t> bucket_t;

typedef Affine_t<fp2_t> affine_fp2_t;
typedef jacobian_t<fp2_t> point_fp2_t;
typedef xyzz_t<fp2_t> bucket_fp2_t;

typedef fr_t scalar_t;

#define SPPARK_DONT_INSTANTIATE_TEMPLATES
#include "msm/pippenger.cuh"

namespace sppark::bn254 {
#include "ntt/ntt.cuh"
} // namespace sppark::bn254
using namespace sppark::bn254;

#include "util.cuh"

#include "groth16_coeffs.cuh"
#include "groth16_prover.cuh"
#include "groth16_srs.cuh"

struct SetupParams {
  const char* pcoeffs_path;
  const char* fres_path;
  const char* srs_path;
};

struct ProveParams {
  const char* public_path;
  const char* proof_path;
  const fr_t* witness;
};

namespace {
struct PersistentProverCache {
  std::mutex mutex;
  std::unique_ptr<SRS> srs;
  std::string srs_path;
};

PersistentProverCache& persistent_cache() {
  // CUDA may unload its driver before process-scope C++ destructors run.
  // Deliberately retain the process-lifetime cache and let the operating
  // system reclaim it after all verified receipts have been written.
  static auto* cache = new PersistentProverCache();
  return *cache;
}
} // namespace

extern "C" const char* risc0_groth16_cuda_prove(SetupParams* setup_params,
                                                ProveParams* prover_params) {
  auto& cache = persistent_cache();
  std::lock_guard<std::mutex> lock(cache.mutex);
  try {
    const bool setup_changed = !cache.srs ||
                               cache.srs_path != setup_params->srs_path;
    if (setup_changed) {
      cache.srs.reset();
      cache.srs = std::make_unique<SRS>(0, setup_params->srs_path);
      cache.srs_path = setup_params->srs_path;
    }
    // groth16_prover owns mutable polynomial, MSM, witness, and stream state.
    // Reusing it across different receipts can yield a locally invalid proof.
    // Retain the immutable SRS, but rebuild this mutable per-proof workspace.
    groth16_prover prover(
        *cache.srs, setup_params->pcoeffs_path, setup_params->fres_path);
    groth16_proof proof =
        prover.prove(prover_params->public_path, prover_params->witness);
    write_proof_file(prover_params->proof_path, proof);
  } catch (const std::exception& err) {
    // Do not retain a potentially poisoned CUDA stream or partial setup after
    // any proving failure. The next call must rebuild from authenticated
    // assets and either verify or fail closed again.
    cache.srs.reset();
    cache.srs_path.clear();
    return strdup(err.what());
  }
  return nullptr;
}

#ifdef SRS_READ_COEFFS

extern "C" const char* risc0_groth16_cuda_setup(SetupParams* params) {
  try {
    SRS sw(0, params->srs_path);
    groth16_prover prover(sw);
    prover.write_precomputations_to_file(params->fres_path, params->pcoeffs_path);
  } catch (const std::exception& err) {
    return strdup(err.what());
  }
  return nullptr;
}

#endif // SRS_READ_COEFFS
