#include <Arduino.h>
#define RADIOLIB_GODMODE 1
#include <RadioLib.h>
#include <SPI.h>

constexpr char kBuild[] = "w12-flrc-profile-v2";
constexpr char kDriver[] = "510e00cfb05bbc3c2b7b524262785454944adb6e";
constexpr uint32_t kTxTimeoutUs = 100000;
constexpr uint32_t kEchoTimeoutUs = 50000;
constexpr size_t kMinLength = 12;
constexpr size_t kMaxLength = 255;
constexpr uint32_t kRxIrqs = RADIOLIB_LR2021_IRQ_RX_DONE | RADIOLIB_LR2021_IRQ_CRC_ERROR | RADIOLIB_LR2021_IRQ_LEN_ERROR |
                             RADIOLIB_LR2021_IRQ_TIMEOUT | RADIOLIB_LR2021_IRQ_ERROR | RADIOLIB_LR2021_IRQ_CMD_ERROR;
uint8_t kSync[] = {0x2D, 0x01, 0x4B, 0x1D};
LR2021 radio = new Module(8, 14, 12, 13, SPI, SPISettings(4000000, MSBFIRST, SPI_MODE0));
const uint32_t rfSwitchPins[Module::RFSWITCH_MAX_PINS] = {
    RADIOLIB_LR2021_DIO5, RADIOLIB_LR2021_DIO6, RADIOLIB_LR2021_DIO9, RADIOLIB_LR2021_DIO10, RADIOLIB_LR2021_DIO11,
};
const Module::RfSwitchMode_t rfSwitchTable[] = {
    {LR2021::MODE_STBY, {LOW, LOW, LOW, LOW, LOW}},   {LR2021::MODE_RX, {LOW, LOW, LOW, LOW, HIGH}},
    {LR2021::MODE_TX, {LOW, LOW, HIGH, LOW, HIGH}},   {LR2021::MODE_RX_HF, {LOW, HIGH, LOW, LOW, LOW}},
    {LR2021::MODE_TX_HF, {HIGH, LOW, LOW, LOW, LOW}}, END_OF_MODE_TABLE,
};

volatile bool irqSeen = false;
volatile uint32_t irqAt = 0;
bool irqPolled = false;
uint32_t lastIrqPollUs = 0;
uint32_t recoveredIrqs = 0;
bool errorRecovery = false;
bool ready = false;
bool receiving = false;
bool sending = false;
bool operationActive = false;
bool stopRequested = false;
int16_t quiesceError = RADIOLIB_ERR_NONE;
uint32_t runId;
uint32_t sequence = 0;
uint32_t echoDelayUs = 2000;
uint8_t crcBytes = 4;
uint8_t chipMajor = 0, chipMinor = 0;
char command[96];
size_t commandLength = 0;
bool commandOverflow = false;

void ARDUINO_ISR_ATTR onIrq()
{
    if (!irqSeen)
        irqAt = micros();
    irqSeen = true;
}

void clearEdge()
{
    noInterrupts();
    irqSeen = false;
    irqAt = 0;
    irqPolled = false;
    interrupts();
}

uint32_t decode32(const uint8_t *data)
{
    return uint32_t(data[0]) | uint32_t(data[1]) << 8 | uint32_t(data[2]) << 16 | uint32_t(data[3]) << 24;
}

void encode32(uint8_t *data, uint32_t value)
{
    for (size_t i = 0; i < 4; ++i)
        data[i] = value >> (8 * i);
}

uint8_t pattern(uint32_t peerRun, uint32_t seq, size_t offset)
{
    return uint8_t((peerRun >> ((offset % 4) * 8)) ^ (seq * 31) ^ (offset * 17));
}

void makeFrame(uint8_t *data, size_t length, uint32_t seq)
{
    memcpy(data, "W12F", 4);
    encode32(data + 4, runId);
    encode32(data + 8, seq);
    for (size_t i = kMinLength; i < length; ++i)
        data[i] = pattern(runId, seq, i);
}

bool validFrame(const uint8_t *data, size_t length)
{
    if (length < kMinLength || length > kMaxLength || memcmp(data, "W12F", 4))
        return false;
    for (size_t i = kMinLength; i < length; ++i)
        if (data[i] != pattern(decode32(data + 4), decode32(data + 8), i))
            return false;
    return true;
}

int16_t armReceive(uint32_t &armUs)
{
    clearEdge();
    uint32_t started = micros();
    int16_t status =
        radio.startReceive(RADIOLIB_LR2021_RX_TIMEOUT_INF, RADIOLIB_IRQ_RX_DEFAULT_FLAGS,
                           (1UL << RADIOLIB_IRQ_RX_DONE) | (1UL << RADIOLIB_IRQ_CRC_ERR) | (1UL << RADIOLIB_IRQ_HEADER_ERR));
    if (status == RADIOLIB_ERR_NONE)
        if (errorRecovery)
            status = radio.setDioIrqConfig(8, kRxIrqs);
    armUs = micros() - started;
    receiving = status == RADIOLIB_ERR_NONE;
    lastIrqPollUs = micros();
    return status;
}

int16_t quiesce()
{
    int16_t status = receiving ? radio.finishReceive() : radio.standby();
    receiving = false;
    clearEdge();
    if (status != RADIOLIB_ERR_NONE) {
        quiesceError = status;
        ready = false;
        stopRequested = true;
    }
    return quiesceError;
}

void reportStopped(int16_t status)
{
    Serial.printf("{\"event\":\"stopped\",\"status\":%d,\"quiescent\":%s}\n", status,
                  status == RADIOLIB_ERR_NONE ? "true" : "false");
}

int16_t readFrame(uint8_t *frame, size_t length, uint32_t flags)
{
    // readData's zero length means "read the entire FIFO"; never pass an unbounded length.
    if (!(flags & RADIOLIB_LR2021_IRQ_RX_DONE) ||
        (flags & (RADIOLIB_LR2021_IRQ_LEN_ERROR | RADIOLIB_LR2021_IRQ_ERROR | RADIOLIB_LR2021_IRQ_CMD_ERROR)) ||
        length < kMinLength || length > kMaxLength) {
        int16_t status = radio.clearRxFifo();
        if (status != RADIOLIB_ERR_NONE)
            return status;
        return (flags & RADIOLIB_LR2021_IRQ_CRC_ERROR) ? RADIOLIB_ERR_CRC_MISMATCH : RADIOLIB_ERR_UNKNOWN;
    }
    return radio.readData(frame, length);
}

void info()
{
    uint64_t mac = ESP.getEfuseMac();
    char boardId[18];
    snprintf(boardId, sizeof(boardId), "%02X:%02X:%02X:%02X:%02X:%02X", uint8_t(mac), uint8_t(mac >> 8), uint8_t(mac >> 16),
             uint8_t(mac >> 24), uint8_t(mac >> 32), uint8_t(mac >> 40));
    Serial.printf("{\"event\":\"info\",\"build\":\"%s\",\"board_id\":\"%s\","
                  "\"run\":%lu,\"ready\":%s,"
                  "\"freq_mhz\":915.0,\"bitrate_kbps\":1040,\"cr\":\"3/"
                  "4\",\"shaping\":\"BT0.5\","
                  "\"preamble_bits\":32,\"sync_hex\":\"2D014B1D\",\"crc_bytes\":%"
                  "u,\"drive_dbm\":-9,"
                  "\"ramp_us\":48,\"role\":\"%s\",\"driver_version\":\"%s\","
                  "\"chip_major\":%u,\"chip_minor\":%u,\"error_recovery\":%s}\n",
                  kBuild, boardId, (unsigned long)runId, ready ? "true" : "false", crcBytes,
                  sending     ? "tx"
                  : receiving ? "rx"
                              : "idle",
                  kDriver, chipMajor, chipMinor, errorRecovery ? "true" : "false");
}

void stats()
{
    uint16_t packets = 0, crcErrors = 0, lengthErrors = 0;
    int16_t status = radio.getFlrcRxStats(&packets, &crcErrors, &lengthErrors);
    Serial.printf("{\"event\":\"stats\",\"run\":%lu,\"status\":%d,\"packets\":%u,\"crc_errors\":%u,"
                  "\"length_errors\":%u,\"irq\":%lu,\"dio_level\":%d,\"recovered_irqs\":%lu}\n",
                  (unsigned long)runId, status, packets, crcErrors, lengthErrors, (unsigned long)radio.getIrqFlags(),
                  digitalRead(14), (unsigned long)recoveredIrqs);
}

void readCommands();

bool waitEdge(uint32_t started, uint32_t timeoutUs)
{
    while (!irqSeen && uint32_t(micros() - started) < timeoutUs) {
        readCommands();
        delayMicroseconds(5);
    }
    return irqSeen;
}

struct TxMeasurement {
    int16_t status;
    bool done;
    uint32_t started;
    uint32_t launchAt;
    uint32_t stageUs;
    uint32_t launchUs;
    uint32_t startCallUs;
    uint32_t doneUs;
    uint32_t finishUs;
};
TxMeasurement transmitFrame(const uint8_t *data, size_t length);

TxMeasurement transmitFrame(const uint8_t *data, size_t length)
{
    operationActive = true;
    TxMeasurement result = {};
    clearEdge();
    result.started = micros();
    RadioModeConfig_t config = {};
    config.transmit.data = data;
    config.transmit.len = length;
    result.status = radio.stageMode(RADIOLIB_RADIO_MODE_TX, &config);
    result.stageUs = micros() - result.started;
    result.launchAt = micros();
    if (result.status == RADIOLIB_ERR_NONE)
        result.status = radio.launchMode();
    result.launchUs = micros() - result.launchAt;
    result.startCallUs = micros() - result.started;
    bool edge = result.status == RADIOLIB_ERR_NONE && waitEdge(result.started, kTxTimeoutUs);
    uint32_t flags = edge ? radio.getIrqFlags() : 0;
    result.done = edge && (flags & RADIOLIB_LR2021_IRQ_TX_DONE);
    result.doneUs = result.done ? uint32_t(irqAt - result.started) : 0;
    if (result.status == RADIOLIB_ERR_NONE && !result.done)
        result.status = RADIOLIB_ERR_TX_TIMEOUT;
    uint32_t finishing = micros();
    int16_t finishStatus = radio.finishTransmit();
    result.finishUs = micros() - finishing;
    if (result.status == RADIOLIB_ERR_NONE)
        result.status = finishStatus;
    operationActive = false;
    return result;
}

void runFrames(size_t length, uint32_t count, uint32_t gapMs)
{
    int16_t initialStopStatus = quiesce();
    if (initialStopStatus != RADIOLIB_ERR_NONE) {
        reportStopped(initialStopStatus);
        return;
    }
    sending = true;
    stopRequested = false;
    Serial.printf("{\"event\":\"run_start\",\"run\":%lu,\"length\":%u,\"count\":%"
                  "lu,\"gap_ms\":%lu}\n",
                  (unsigned long)runId, unsigned(length), (unsigned long)count, (unsigned long)gapMs);
    uint32_t completed = 0;
    for (; completed < count && !stopRequested; ++completed) {
        uint8_t frame[kMaxLength], echo[kMaxLength];
        uint32_t seq = sequence++;
        makeFrame(frame, length, seq);
        uint32_t toa = radio.getTimeOnAir(length);
        TxMeasurement tx = transmitFrame(frame, length);
        uint32_t armUs = 0, rttUs = 0, rxReadyAfterTxDoneUs = 0;
        int16_t rxStatus = RADIOLIB_ERR_RX_TIMEOUT;
        int16_t rxArmStatus = RADIOLIB_ERR_UNKNOWN;
        bool rxArmAttempted = false;
        bool matched = false;
        if (tx.status == RADIOLIB_ERR_NONE && !stopRequested) {
            rxArmAttempted = true;
            rxArmStatus = rxStatus = armReceive(armUs);
            if (rxStatus == RADIOLIB_ERR_NONE)
                rxReadyAfterTxDoneUs = micros() - (tx.started + tx.doneUs);
            if (rxStatus == RADIOLIB_ERR_NONE) {
                uint32_t waiting = micros();
                if (waitEdge(waiting, kEchoTimeoutUs)) {
                    rttUs = irqAt - tx.started;
                    size_t receivedLength = radio.getPacketLength();
                    rxStatus = readFrame(echo, receivedLength, radio.getIrqFlags());
                    matched = rxStatus == RADIOLIB_ERR_NONE && receivedLength == length && memcmp(frame, echo, length) == 0;
                } else
                    rxStatus = RADIOLIB_ERR_RX_TIMEOUT;
            }
        }
        quiesce();
        Serial.printf("{\"event\":\"attempt\",\"run\":%lu,\"seq\":%lu,\"length\":%u,\"tx_"
                      "status\":%d,"
                      "\"tx_done\":%s,\"start_call_us\":%lu,\"tx_done_us\":%lu,\"finish_tx_"
                      "us\":%lu,"
                      "\"stage_tx_us\":%lu,\"launch_call_us\":%lu,\"launch_to_tx_done_us\":%"
                      "lu,"
                      "\"rx_ready_after_tx_done_us\":%lu,"
                      "\"rx_arm_us\":%lu,\"rx_arm_attempted\":%s,\"rx_arm_status\":%d,"
                      "\"echo\":%s,\"rx_status\":%d,\"rtt_us\":%lu,"
                      "\"driver_toa_us\":%lu}\n",
                      (unsigned long)runId, (unsigned long)seq, unsigned(length), tx.status, tx.done ? "true" : "false",
                      (unsigned long)tx.startCallUs, (unsigned long)tx.doneUs, (unsigned long)tx.finishUs,
                      (unsigned long)tx.stageUs, (unsigned long)tx.launchUs,
                      tx.done ? (unsigned long)(tx.started + tx.doneUs - tx.launchAt) : 0, (unsigned long)rxReadyAfterTxDoneUs,
                      (unsigned long)armUs, rxArmAttempted ? "true" : "false", rxArmStatus, matched ? "true" : "false", rxStatus,
                      (unsigned long)rttUs, (unsigned long)toa);
        uint32_t gapStarted = micros();
        while (!stopRequested && uint32_t(micros() - gapStarted) < gapMs * 1000) {
            readCommands();
            delay(1);
        }
    }
    sending = false;
    int16_t stopStatus = quiesce();
    Serial.printf("{\"event\":\"run_end\",\"run\":%lu,\"attempts\":%lu,\"requested_count\":%lu,"
                  "\"stopped\":%s,\"complete\":%s}\n",
                  (unsigned long)runId, (unsigned long)completed, (unsigned long)count, stopRequested ? "true" : "false",
                  completed == count && !stopRequested ? "true" : "false");
    if (stopRequested)
        reportStopped(stopStatus);
}

void processCommand(const char *line)
{
    if (!strcmp(line, "INFO")) {
        info();
        return;
    }
    if (!strcmp(line, "STATS") && !sending && !operationActive) {
        stats();
        return;
    }
    if (!strcmp(line, "STOP")) {
        stopRequested = true;
        if (!sending && !operationActive) {
            reportStopped(quiesce());
        }
        return;
    }
    if (sending || operationActive) {
        Serial.println("{\"event\":\"error\",\"reason\":\"busy\"}");
        return;
    }
    if (!strcmp(line, "RX") && ready) {
        int16_t stopStatus = quiesce();
        if (stopStatus != RADIOLIB_ERR_NONE) {
            reportStopped(stopStatus);
            return;
        }
        stopRequested = false;
        uint32_t armUs;
        int16_t status = armReceive(armUs);
        Serial.printf("{\"event\":\"rx_ready\",\"status\":%d,\"arm_us\":%lu}\n", status, (unsigned long)armUs);
        return;
    }
    unsigned long value, count, gap;
    char tail;
    if (sscanf(line, "RECOVERY %lu %c", &value, &tail) == 1 && !receiving && value <= 1) {
        errorRecovery = value != 0;
        Serial.printf("{\"event\":\"recovery\",\"enabled\":%s}\n", errorRecovery ? "true" : "false");
        return;
    }
    if (sscanf(line, "RUN %lu %lu %lu %c", &value, &count, &gap, &tail) == 3 && ready && value >= kMinLength &&
        value <= kMaxLength && count > 0 && count <= 100000 && gap <= 1000) {
        runFrames(value, count, gap);
        return;
    }
    if (sscanf(line, "DELAY %lu %c", &value, &tail) == 1 && !receiving && value <= 50000) {
        echoDelayUs = value;
        Serial.printf("{\"event\":\"delay\",\"us\":%lu}\n", value);
        return;
    }
    if (sscanf(line, "CRC %lu %c", &value, &tail) == 1 && !receiving && ready && (value == 2 || value == 4)) {
        int16_t status = radio.setCRC(value);
        if (status == RADIOLIB_ERR_NONE)
            crcBytes = value;
        Serial.printf("{\"event\":\"crc\",\"bytes\":%u,\"status\":%d}\n", crcBytes, status);
        return;
    }
    Serial.println("{\"event\":\"error\",\"reason\":\"invalid_command_or_not_ready\"}");
}

void readCommands()
{
    while (Serial.available()) {
        char c = Serial.read();
        if (c == '\r')
            continue;
        if (c == '\n') {
            command[commandLength] = 0;
            commandLength = 0;
            if (commandOverflow)
                Serial.println("{\"event\":\"error\",\"reason\":\"command_too_long\"}");
            else
                processCommand(command);
            commandOverflow = false;
        } else if (commandLength + 1 < sizeof(command))
            command[commandLength++] = c;
        else
            commandOverflow = true;
    }
}

void receiveFrame()
{
    uint32_t rxEdge = irqAt;
    bool polled = irqPolled;
    uint32_t flags = radio.getIrqFlags();
    uint8_t frame[kMaxLength] = {};
    size_t length = radio.getPacketLength();
    uint32_t reading = micros();
    int16_t status = readFrame(frame, length, flags);
    uint32_t readUs = micros() - reading;
    bool valid = status == RADIOLIB_ERR_NONE && validFrame(frame, length);
    uint32_t peerRun = valid ? decode32(frame + 4) : 0;
    uint32_t seq = valid ? decode32(frame + 8) : 0;
    int16_t stopStatus = quiesce();
    TxMeasurement echo = {};
    echo.status = RADIOLIB_ERR_UNKNOWN;
    if (valid && !stopRequested) {
        delayMicroseconds(echoDelayUs);
        echo = transmitFrame(frame, length);
    }
    uint32_t rearmUs = 0;
    int16_t rearmStatus = stopRequested ? RADIOLIB_ERR_NONE : armReceive(rearmUs);
    Serial.printf("{\"event\":\"rx\",\"run\":%lu,\"peer_run\":%lu,\"seq\":%lu,\"length\":%u,\"status\":"
                  "%d,"
                  "\"payload_valid\":%s,\"irq\":%lu,\"read_us\":%lu,\"echo_start_us\":%lu,"
                  "\"echo_done_us\":%lu,\"echo_status\":%d,\"rx_rearm_us\":%lu,\"rearm_"
                  "status\":%d,\"delay_us\":%lu,\"irq_source\":\"%s\"}\n",
                  (unsigned long)runId, (unsigned long)peerRun, (unsigned long)seq, unsigned(length), status,
                  valid ? "true" : "false", (unsigned long)flags, (unsigned long)readUs,
                  valid ? (unsigned long)(echo.started - rxEdge) : 0,
                  valid && echo.done ? (unsigned long)(echo.started + echo.doneUs - rxEdge) : 0, echo.status,
                  (unsigned long)rearmUs, rearmStatus, (unsigned long)echoDelayUs, polled ? "poll" : "dio");
    if (stopRequested)
        reportStopped(stopStatus);
}

void setup()
{
    // Native USB's default 256-byte TX buffer is smaller than an INFO or attempt record.
    Serial.setTxBufferSize(4096);
    Serial.begin(115200);
    runId = esp_random();
    // Schematic IO4_PA_EN_M supplies the 915 MHz frontend; IO3_PA_EN_G
    // supplies 2.4 GHz.
    pinMode(3, OUTPUT);
    digitalWrite(3, LOW);
    pinMode(4, OUTPUT);
    digitalWrite(4, HIGH);
    SPI.begin(9, 11, 10, 8);
    radio.irqDioNum = 8;
    int16_t status = radio.beginFLRC(915.0f, 1040, RADIOLIB_LR2021_FLRC_CR_3_4, -9, 32, RADIOLIB_SHAPING_0_5, 0.0f);
    if (status == RADIOLIB_ERR_NONE)
        status = radio.setSyncWord(kSync, sizeof(kSync));
    if (status == RADIOLIB_ERR_NONE)
        status = radio.setCRC(4);
    if (status == RADIOLIB_ERR_NONE)
        status = radio.setOutputPower(-9, 48);
    if (status == RADIOLIB_ERR_NONE)
        status = radio.variablePacketLengthMode(kMaxLength);
    if (status == RADIOLIB_ERR_NONE)
        radio.setRfSwitchTable(rfSwitchPins, rfSwitchTable);
    if (status == RADIOLIB_ERR_NONE)
        status = radio.getVersion(&chipMajor, &chipMinor);
    ready = status == RADIOLIB_ERR_NONE;
    attachInterrupt(digitalPinToInterrupt(14), onIrq, RISING);
    quiesce();
    Serial.printf("{\"event\":\"boot\",\"build\":\"%s\",\"status\":%d}\n", kBuild, status);
}

void loop()
{
    readCommands();
    if (errorRecovery && receiving && !irqSeen && uint32_t(micros() - lastIrqPollUs) >= 20000) {
        lastIrqPollUs = micros();
        uint32_t flags = radio.getIrqFlags();
        noInterrupts();
        if (!irqSeen && (flags & kRxIrqs)) {
            irqAt = micros();
            irqSeen = true;
            irqPolled = true;
            ++recoveredIrqs;
        }
        interrupts();
    }
    if (receiving && irqSeen)
        receiveFrame();
    delayMicroseconds(5);
}
