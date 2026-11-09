#include <cstdint>
#include <cstddef>
#include <cstdio>
#pragma pack(push,1)
struct atom_common_table_header {uint16_t structuresize;uint8_t format_revision,content_revision;};
#pragma pack(pop)
#include "sources/smu11_driver_if_sienna_cichlid.h"
#include "sources/smu_v11_0_7_pptable.h"
int main(){
#define OFFSET(t,f) printf("\"%s.%s\":%zu,\n",#t,#f,offsetof(t,f));
printf("{\n");
OFFSET(smu_11_0_7_powerplay_table,smc_pptable)
OFFSET(smu_11_0_7_powerplay_table,power_saving_clock)
OFFSET(smu_11_0_7_power_saving_clock_table,max)
OFFSET(smu_11_0_7_power_saving_clock_table,min)
OFFSET(PPTable_t,SocketPowerLimitAc)
OFFSET(PPTable_t,SocketPowerLimitDc)
OFFSET(PPTable_t,DpmDescriptor)
OFFSET(PPTable_t,FreqTableGfx)
OFFSET(PPTable_t,FreqTableUclk)
OFFSET(PPTable_t,GfxclkFinit)
OFFSET(PPTable_t,GfxclkFidle)
printf("\"pp_table_size\":%zu,\"smc_table_size\":%zu,\"gfx_levels\":%d,\"mem_levels\":%d,\"power_limits\":%d}\n",sizeof(smu_11_0_7_powerplay_table),sizeof(PPTable_t),NUM_GFXCLK_DPM_LEVELS,NUM_UCLK_DPM_LEVELS,PPT_THROTTLER_COUNT);
}
