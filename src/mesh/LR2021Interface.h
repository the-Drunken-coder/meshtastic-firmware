#pragma once
#if RADIOLIB_EXCLUDE_LR2021 != 1
#include "LR20x0Interface.h"

/**
 * Our adapter for LR2021 radios
 */
class LR2021Interface : public LR20x0Interface<LR2021>
{
  public:
    LR2021Interface(LockingArduinoHal *hal, RADIOLIB_PIN_TYPE cs, RADIOLIB_PIN_TYPE irq, RADIOLIB_PIN_TYPE rst,
                    RADIOLIB_PIN_TYPE busy);
    bool wideLora() override;
    bool init() override;
    bool reconfigure() override;
    bool sleep() override;

  protected:
    void startReceive() override;
    void setStandby() override;
    bool isChannelActive() override;
    bool isActivelyReceiving() override;
    int16_t getCurrentRSSI() override;
    void addReceiveMetadata(meshtastic_MeshPacket *mp) override;
    uint32_t getPacketTime(uint32_t length, bool received) override;
    bool recoverChipStateLoss() override;
    bool receiveIrqPending() override;
    bool validReceiveIrq() override;
    bool validTransmitIrq() override;
    bool armTransmitBeforeStart() override;
    void onTransmitStarted() override;
    void handleSoftwareLoraIrqPoll() override;
#if MESHTASTIC_W12_BENCHMARK || defined(PIO_UNIT_TESTING)
    W12ActiveReceiveState readW12ActiveReceiveState() override;
    bool readW12RxLiveness(W12RxLivenessSample &sample) override;
    bool readW12RxRecovery(W12RxRecoverySample &sample) override;
    bool performW12RxRearm(W12RxRearmResult &result) override;
#endif

  private:
    bool beginFlrc();
    int16_t standbyFlrc();
};
#endif
