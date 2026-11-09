// Ordinary bounded HIP dispatch: read HW_ID1, verify integer ALU results.
// No CU mask, privileged shader instruction, trap, MMIO, or power change.
#include <hip/hip_runtime.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <array>

#define HIP(call) do { auto e = (call); if (e != hipSuccess) { \
  fprintf(stderr, "%s: %s\n", #call, hipGetErrorString(e)); exit(1); } } while (0)

__global__ void observe(uint32_t *ids, uint32_t *values, uint32_t salt) {
  const uint32_t idx = blockIdx.x * blockDim.x + threadIdx.x;
  uint32_t hw;
  asm volatile("s_getreg_b32 %0, hwreg(HW_REG_HW_ID1)" : "=s"(hw));
  uint32_t v = idx ^ salt;
  #pragma unroll 1
  for (unsigned j = 0; j < 64; j++) v = v * 1664525u + 1013904223u;
  values[idx] = v;
  if ((threadIdx.x & 31) == 0) ids[idx / 32] = hw;
}

int main(int argc, char **argv) {
  if (argc != 2) { fprintf(stderr, "usage: navi21-wave-map OUTPUT_DIRECTORY\n"); return 2; }
  int devices;
  HIP(hipGetDeviceCount(&devices));
  printf("{\"wave_size\":32,\"samples\":[\n");
  bool first = true;
  for (int dev = 0; dev < devices; dev++) {
    HIP(hipSetDevice(dev));
    hipDeviceProp_t p;
    HIP(hipGetDeviceProperties(&p, dev));
    if (p.warpSize != 32) { fprintf(stderr, "Unexpected wave size\n"); return 3; }
    char bdf[32]; HIP(hipDeviceGetPCIBusId(bdf, sizeof(bdf), dev));
    for (int run = 0; run < 3; run++) {
      unsigned threads = run == 2 ? 256 : 128;
      unsigned blocks = run == 0 ? 4096 : 16384;
      unsigned n = threads * blocks, waves = n / 32;
      uint32_t *d_ids, *d_values;
      HIP(hipMalloc(&d_ids, waves * sizeof(uint32_t)));
      HIP(hipMalloc(&d_values, n * sizeof(uint32_t)));
      hipEvent_t start, stop;
      HIP(hipEventCreate(&start)); HIP(hipEventCreate(&stop));
      HIP(hipEventRecord(start));
      observe<<<blocks, threads>>>(d_ids, d_values, 0x12345678u + run);
      HIP(hipGetLastError()); HIP(hipEventRecord(stop)); HIP(hipEventSynchronize(stop));
      float ms; HIP(hipEventElapsedTime(&ms, start, stop));
      std::vector<uint32_t> ids(waves), values(n);
      HIP(hipMemcpy(ids.data(), d_ids, waves * sizeof(uint32_t), hipMemcpyDeviceToHost));
      HIP(hipMemcpy(values.data(), d_values, n * sizeof(uint32_t), hipMemcpyDeviceToHost));
      uint64_t errors = 0;
      for (unsigned i = 0; i < n; i++) {
        uint32_t v = i ^ (0x12345678u + run);
        for (unsigned j = 0; j < 64; j++) v = v * 1664525u + 1013904223u;
        errors += v != values[i];
      }
      // SQ_WAVE_HW_ID1: SE[19:18], SA[16], WGP[13:10], SIMD[9:8].
      unsigned wgp_masks[4][2] = {}, simd_masks[4][2][16] = {};
      unsigned counts[4][2] = {}, bad_id = 0;
      for (auto id : ids) {
        unsigned se = (id >> 18) & 3, sa = (id >> 16) & 1;
        unsigned wgp = (id >> 10) & 15, simd = (id >> 8) & 3;
        wgp_masks[se][sa] |= 1u << wgp; simd_masks[se][sa][wgp] |= 1u << simd;
        counts[se][sa]++; bad_id += wgp >= 5;
      }
      char name[512]; snprintf(name, sizeof(name), "%s/hip%d-run%d-hwid.bin", argv[1], dev, run);
      FILE *f = fopen(name, "wb"); if (!f) { perror(name); return 4; }
      if (fwrite(ids.data(), sizeof(uint32_t), ids.size(), f) != ids.size()) return 5;
      fclose(f);
      printf("%s{\"hip\":%d,\"bdf\":\"%s\",\"run\":%d,\"reported_cu\":%d,\"blocks\":%u,\"threads\":%u,\"waves\":%u,\"checked_values\":%u,\"errors\":%llu,\"bad_id\":%u,\"kernel_ms\":%.6f,\"banks\":[",
             first ? "" : ",\n", dev, bdf, run, p.multiProcessorCount, blocks, threads, waves, n,
             (unsigned long long)errors, bad_id, ms);
      first = false;
      for (unsigned se = 0; se < 4; se++) for (unsigned sa = 0; sa < 2; sa++) {
        printf("%s{\"se\":%u,\"sh\":%u,\"wgp_mask\":%u,\"waves\":%u,\"simd_masks\":[",
               se || sa ? "," : "", se, sa, wgp_masks[se][sa], counts[se][sa]);
        for (unsigned w = 0; w < 5; w++) printf("%s%u", w ? "," : "", simd_masks[se][sa][w]);
        printf("]}");
      }
      printf("]}"); fflush(stdout);
      HIP(hipEventDestroy(start)); HIP(hipEventDestroy(stop));
      HIP(hipFree(d_ids)); HIP(hipFree(d_values));
      if (errors || bad_id) return 6;
    }
  }
  printf("\n]}\n");
}
