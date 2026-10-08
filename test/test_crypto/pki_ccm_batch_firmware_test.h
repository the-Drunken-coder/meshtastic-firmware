#pragma once

#include "pki_ccm_batch.h"

namespace pki_ccm_batch_firmware_test
{

bool compareBoundaries(pki_ccm_batch::AesBackend &batchBackend);
bool checkTamperAndWipe(pki_ccm_batch::AesBackend &batchBackend);
bool checkWireFramingAndCapacity(pki_ccm_batch::AesBackend &batchBackend);
bool runAll(pki_ccm_batch::AesBackend &batchBackend);

#if defined(PIO_UNIT_TESTING)
bool runNativePolicyTests();
#endif

} // namespace pki_ccm_batch_firmware_test
