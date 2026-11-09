// Short stock rocBLAS FP16-input / FP32-output GEMM and GEMV controls.
// No topology, clock, power or CU mask changes. CPU checks use exact small ints.
#include <hip/hip_runtime.h>
#include <rocblas/rocblas.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cmath>
#include <algorithm>

#define HIP(x) do { auto hip_error__=(x); if(hip_error__!=hipSuccess){fprintf(stderr,"%s: %s\n",#x,hipGetErrorString(hip_error__));exit(1);} }while(0)
#define RB(x) do { auto rb_error__=(x); if(rb_error__!=rocblas_status_success){fprintf(stderr,"%s: rocBLAS %d\n",#x,(int)rb_error__);exit(2);} }while(0)

__global__ void fill_a(_Float16 *a, size_t n) {
  size_t i=(size_t)blockIdx.x*blockDim.x+threadIdx.x;
  if(i<n) a[i]=(_Float16)((int)(i%7)-3);
}
__global__ void fill_b(_Float16 *b, size_t n) {
  size_t i=(size_t)blockIdx.x*blockDim.x+threadIdx.x;
  if(i<n) b[i]=(_Float16)((int)(i%5)-2);
}

int main() {
  int nd; HIP(hipGetDeviceCount(&nd)); bool first=true;
  printf("{\"samples\":[\n");
  for(int dev=0;dev<nd;dev++) {
    HIP(hipSetDevice(dev)); char bdf[32]; HIP(hipDeviceGetPCIBusId(bdf,sizeof(bdf),dev));
    rocblas_handle h; RB(rocblas_create_handle(&h));
    for(int kind=0;kind<2;kind++) {
      int m=kind?16384:4096, n=kind?1:512, k=kind?8192:4096;
      size_t na=(size_t)m*k, nb=(size_t)k*n, nc=(size_t)m*n;
      _Float16 *a,*b; float *c;
      HIP(hipMalloc(&a,na*2));HIP(hipMalloc(&b,nb*2));HIP(hipMalloc(&c,nc*4));
      fill_a<<<(na+255)/256,256>>>(a,na);fill_b<<<(nb+255)/256,256>>>(b,nb);HIP(hipGetLastError());
      float alpha=1,beta=0;
      auto gemm=[&](){ RB(rocblas_gemm_ex(h,rocblas_operation_none,rocblas_operation_none,m,n,k,
            &alpha,a,rocblas_datatype_f16_r,m,b,rocblas_datatype_f16_r,k,
            &beta,c,rocblas_datatype_f32_r,m,c,rocblas_datatype_f32_r,m,
            rocblas_datatype_f32_r,rocblas_gemm_algo_standard,0,0)); };
      for(int i=0;i<5;i++)gemm();HIP(hipDeviceSynchronize());
      hipEvent_t s,e;HIP(hipEventCreate(&s));HIP(hipEventCreate(&e));
      std::vector<float> times;
      for(int i=0;i<7;i++) {HIP(hipEventRecord(s));gemm();HIP(hipEventRecord(e));HIP(hipEventSynchronize(e));float ms;HIP(hipEventElapsedTime(&ms,s,e));times.push_back(ms);}
      unsigned errors=0; float maxerr=0;
      for(int v=0;v<64;v++) {
        int row=(v*251)%m,col=(v*67)%n;float actual;
        HIP(hipMemcpy(&actual,c+(size_t)col*m+row,sizeof(float),hipMemcpyDeviceToHost));
        int expected=0;
        for(int t=0;t<k;t++)expected+=((int)(((size_t)t*m+row)%7)-3)*((int)(((size_t)col*k+t)%5)-2);
        float err=fabsf(actual-expected);errors+=err!=0;maxerr=std::max(maxerr,err);
      }
      std::vector<float> sorted=times;std::sort(sorted.begin(),sorted.end());float med=sorted[3];
      printf("%s{\"hip\":%d,\"bdf\":\"%s\",\"kind\":\"%s\",\"m\":%d,\"n\":%d,\"k\":%d,\"weight_bytes\":%zu,\"cpu_checked\":64,\"errors\":%u,\"max_abs_error\":%.9g,\"median_ms\":%.6f,\"tflops\":%.6f,\"weight_GB_s\":%.6f,\"times_ms\":[",
           first?"":",\n",dev,bdf,kind?"GEMV":"GEMM",m,n,k,na*2,errors,maxerr,med,2.0*m*n*k/(med*1e9),na*2/(med*1e6));first=false;
      for(size_t i=0;i<times.size();i++)printf("%s%.6f",i?",":"",times[i]);printf("]}");fflush(stdout);
      HIP(hipEventDestroy(s));HIP(hipEventDestroy(e));HIP(hipFree(a));HIP(hipFree(b));HIP(hipFree(c));
      if(errors)return 3;
    }
    RB(rocblas_destroy_handle(h));
  }
  printf("\n]}\n");
}
