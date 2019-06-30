/*
* Entropy Source Using Intel's rdseed instruction
* (C) 2015 Jack Lloyd, Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/rdseed.h>
#include <botan/cpuid.h>

#if !defined(BOTAN_USE_GCC_INLINE_ASM)
  #include <immintrin.h>
#endif

namespace Botan {

BOTAN_FUNC_ISA("rdseed")
size_t Intel_Rdseed::poll(RandomNumberGenerator& rng)
   {
   if(CPUID::has_rdseed() && BOTAN_ENTROPY_INTEL_RDSEED_BYTES > 0)
      {
      secure_vector<uint32_t> seed;
      seed.reserve(BOTAN_ENTROPY_INTEL_RDSEED_BYTES / 4);

      for(size_t p = 0; p != BOTAN_ENTROPY_INTEL_RDSEED_BYTES / 4; ++p)
         {
         for(size_t i = 0; i != BOTAN_ENTROPY_RDSEED_RETRIES; ++i)
            {
            uint32_t r = 0;

#if defined(BOTAN_USE_GCC_INLINE_ASM)
            int cf = 0;

            // Encoding of rdseed %eax
            asm(".byte 0x0F, 0xC7, 0xF8; adcl $0,%1" :
                "=a" (r), "=r" (cf) : "0" (r), "1" (cf) : "cc");
#else
            int cf = _rdseed32_step(&r);
#endif
            if(1 == cf)
               {
               seed.push_back(r);
               break;
               }
            }
         }

      rng.add_entropy(reinterpret_cast<const uint8_t*>(seed.data()),
                      seed.size() * sizeof(uint32_t));
      }

   // RDSEED is used but not trusted
   return 0;
   }

}
