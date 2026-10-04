// The "heard on the current LoRa config" mark - src/mesh/NodeDB.cpp and src/mesh/TypeConversions.cpp.
// Each node stores the slot it was last heard on; NodeInfo.heard_on_current_lora is that matching the
// slot the radio is committed to. The regression guarded is a client rolling through presets to scan
// for traffic: nothing may be swept on the way out, and returning to a slot must mark its nodes again.
#include "MeshTypes.h" // BEFORE TestUtil.h - provides WARM_NODE_COUNT / MAX_NUM_NODES via mesh-pb-constants.h
#include "TestUtil.h"
#include <unity.h>

#if defined(ARCH_PORTDUINO)
#define NDB_TEST_ENTRY extern "C"
#else
#define NDB_TEST_ENTRY
#endif

#include "mesh/NodeDB.h"
#include "mesh/RadioInterface.h"
#include "mesh/RadioMode.h"
#include "mesh/TypeConversions.h"
#include <cstring>

// Name and global scope both fixed by the `friend class NodeDBTestShim` declaration in NodeDB.h.
class NodeDBTestShim : public NodeDB
{
  public:
    void clearHot()
    {
        meshNodes->clear();
        numMeshNodes = 0;
    }

    // A node admitted without ever being heard over RF - an all-zero bitfield, as a pre-feature
    // record loaded from disk has.
    void push(NodeNum num)
    {
        meshtastic_NodeInfoLite n = meshtastic_NodeInfoLite_init_zero;
        n.num = num;
        n.last_heard = 1000;
        meshNodes->push_back(n);
        numMeshNodes = meshNodes->size();
    }
};

// Only configuration is exercised; production reconfigure() applies and clamps the LoRa settings.
class ConfigurationRadio : public RadioInterface
{
  public:
    ErrorCode send(meshtastic_MeshPacket *packet) override
    {
        packetPool.release(packet);
        return ERRNO_DISABLED;
    }
    uint32_t getPacketTime(uint32_t, bool = false) override { return 1; }
};

namespace
{

NodeDBTestShim *db = nullptr;
meshtastic_Config_LoRaConfig savedLora;

// Every field the snapshot reads is non-default, so changing one is a real change, not a zero swap.
meshtastic_Config_LoRaConfig baselineLora()
{
    meshtastic_Config_LoRaConfig lora = meshtastic_Config_LoRaConfig_init_zero;
    lora.region = meshtastic_Config_LoRaConfig_RegionCode_EU_868;
    lora.use_preset = true;
    lora.modem_preset = meshtastic_Config_LoRaConfig_ModemPreset_LONG_FAST;
    lora.bandwidth = 250;
    lora.spread_factor = 11;
    lora.coding_rate = 5;
    lora.override_frequency = 869.525f;
    lora.channel_num = 7;
    return lora;
}

uint16_t fp(const meshtastic_Config_LoRaConfig &lora, const char *name)
{
    return loraSlotSnapshotFrom(lora, name).fingerprint();
}

// What a client actually sees: derived at conversion time from the slot the radio is committed to.
bool heard(NodeNum num)
{
    return TypeConversions::ConvertToNodeInfo(db->getMeshNode(num), nullptr, nullptr).heard_on_current_lora;
}

// A decoded packet as updateFrom() sees it coming off the RX pipeline.
meshtastic_MeshPacket rxPacket(NodeNum from)
{
    meshtastic_MeshPacket mp = meshtastic_MeshPacket_init_zero;
    mp.from = from;
    mp.which_payload_variant = meshtastic_MeshPacket_decoded_tag;
    mp.has_rx_time = true;
    mp.rx_time = 1000;
    mp.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_LORA;
    return mp;
}

// Move the radio the way a client's set_config(lora) does, committing to the new slot.
void commitPreset(meshtastic_Config_LoRaConfig_ModemPreset preset)
{
    config.lora.modem_preset = preset;
    db->refreshCommittedLoraSlot();
}

void commitHome()
{
    config.lora = savedLora;
    db->refreshCommittedLoraSlot();
}

} // namespace

void setUp(void)
{
    db->clearHot();
    config.lora = savedLora;
    RadioMode::initialize(config.lora);
    db->setLoraSlotTransient(false);
    db->refreshCommittedLoraSlot();
}

void tearDown(void) {}

// ---------- the fingerprint: what counts as a different slot ---------------------------------

static void test_fingerprint_identicalConfigMatches(void)
{
    const meshtastic_Config_LoRaConfig lora = baselineLora();
    TEST_ASSERT_EQUAL_UINT16(fp(lora, "LongFast"), fp(lora, "LongFast"));
}

static void test_fingerprint_regionIsASlotChange(void)
{
    meshtastic_Config_LoRaConfig other = baselineLora();
    other.region = meshtastic_Config_LoRaConfig_RegionCode_US;
    TEST_ASSERT_NOT_EQUAL_UINT16(fp(baselineLora(), "LongFast"), fp(other, "LongFast"));
}

static void test_fingerprint_presetIsASlotChange(void)
{
    meshtastic_Config_LoRaConfig other = baselineLora();
    other.modem_preset = meshtastic_Config_LoRaConfig_ModemPreset_SHORT_FAST;
    TEST_ASSERT_NOT_EQUAL_UINT16(fp(baselineLora(), "LongFast"), fp(other, "LongFast"));
}

static void test_fingerprint_channelNumChangesSlot(void)
{
    meshtastic_Config_LoRaConfig other = baselineLora();
    other.channel_num = 8;
    TEST_ASSERT_NOT_EQUAL_UINT16(fp(baselineLora(), "LongFast"), fp(other, "LongFast"));
}

static void test_fingerprint_overrideFrequencyIsASlotChange(void)
{
    meshtastic_Config_LoRaConfig other = baselineLora();
    other.override_frequency = 869.4f;
    TEST_ASSERT_NOT_EQUAL_UINT16(fp(baselineLora(), "LongFast"), fp(other, "LongFast"));
}

// Slot is the hash of the primary channel name, so a rename or a scanned QR moves the radio.
static void test_fingerprint_primaryChannelRenameIsASlotChange(void)
{
    const meshtastic_Config_LoRaConfig lora = baselineLora();
    TEST_ASSERT_NOT_EQUAL_UINT16(fp(lora, "LongFast"), fp(lora, "MyMesh"));
}

static void test_fingerprint_usePresetToggleIsASlotChange(void)
{
    meshtastic_Config_LoRaConfig other = baselineLora();
    other.use_preset = false;
    TEST_ASSERT_NOT_EQUAL_UINT16(fp(baselineLora(), "LongFast"), fp(other, "LongFast"));
}

// The dormant half of the preset/custom pair moves nothing on air; editing it must not read as a move.
static void test_fingerprint_dormantModemFieldsIgnoredWhenUsingPreset(void)
{
    meshtastic_Config_LoRaConfig other = baselineLora(); // use_preset = true
    other.bandwidth = 125;
    other.spread_factor = 7;
    other.coding_rate = 8;
    TEST_ASSERT_EQUAL_UINT16(fp(baselineLora(), "LongFast"), fp(other, "LongFast"));
}

static void test_fingerprint_dormantPresetIgnoredWhenNotUsingPreset(void)
{
    meshtastic_Config_LoRaConfig base = baselineLora();
    base.use_preset = false;
    meshtastic_Config_LoRaConfig other = base;
    other.modem_preset = meshtastic_Config_LoRaConfig_ModemPreset_SHORT_FAST;
    TEST_ASSERT_EQUAL_UINT16(fp(base, "LongFast"), fp(other, "LongFast"));
}

static void test_fingerprint_customModemFieldsCountWhenNotUsingPreset(void)
{
    meshtastic_Config_LoRaConfig base = baselineLora();
    base.use_preset = false;
    meshtastic_Config_LoRaConfig bw = base, sf = base, cr = base;
    bw.bandwidth = 125;
    sf.spread_factor = 7;
    cr.coding_rate = 8;
    TEST_ASSERT_NOT_EQUAL_UINT16(fp(base, "LongFast"), fp(bw, "LongFast"));
    TEST_ASSERT_NOT_EQUAL_UINT16(fp(base, "LongFast"), fp(sf, "LongFast"));
    TEST_ASSERT_NOT_EQUAL_UINT16(fp(base, "LongFast"), fp(cr, "LongFast"));
}

static void test_flrc_profileIgnoresRetainedLoraTuning(void)
{
    auto flrc = baselineLora();
    flrc.region = meshtastic_Config_LoRaConfig_RegionCode_US;
    flrc.has_radio_mode = true;
    flrc.radio_mode = meshtastic_Config_LoRaConfig_RadioMode_FLRC;
    auto changed = flrc;
    changed.channel_num = 42;
    changed.override_frequency = 916.0f;
    changed.modem_preset = meshtastic_Config_LoRaConfig_ModemPreset_SHORT_FAST;
    TEST_ASSERT_EQUAL_UINT16(fp(flrc, "LongFast"), fp(changed, "MyMesh"));
    changed.radio_mode = meshtastic_Config_LoRaConfig_RadioMode_LORA;
    TEST_ASSERT_NOT_EQUAL_UINT16(fp(flrc, "LongFast"), fp(changed, "MyMesh"));
}

static void test_flrc_savedSelectionDoesNotMoveActiveReachability(void)
{
    db->updateFrom(rxPacket(0x4444));
    const uint16_t activeSlot = db->committedLoraSlot();
    config.lora.has_radio_mode = true;
    config.lora.radio_mode = meshtastic_Config_LoRaConfig_RadioMode_FLRC;
    db->refreshCommittedLoraSlot();
    TEST_ASSERT_EQUAL_UINT16(activeSlot, db->committedLoraSlot());
    TEST_ASSERT_TRUE(heard(0x4444));

    RadioMode::initialize(config.lora);
    db->refreshCommittedLoraSlot();
    TEST_ASSERT_FALSE(heard(0x4444));
    db->updateFrom(rxPacket(0x4444));
    TEST_ASSERT_TRUE(heard(0x4444));
}

static void test_flrc_receiveDoesNotInventSnr(void)
{
    auto packet = rxPacket(0x4444);
    packet.has_rx_rssi = true;
    packet.rx_snr = 7.0f;
    db->updateFrom(packet);
    TEST_ASSERT_TRUE(nodeInfoLiteHasSnr(db->getMeshNode(packet.from)));

    config.lora.has_radio_mode = true;
    config.lora.radio_mode = meshtastic_Config_LoRaConfig_RadioMode_FLRC;
    RadioMode::initialize(config.lora);
    db->refreshCommittedLoraSlot();
    packet.rx_snr = 0;
    packet.rx_snr_unavailable = true;
    db->updateFrom(packet);
    const auto *node = db->getMeshNode(packet.from);
    TEST_ASSERT_FALSE(nodeInfoLiteHasSnr(node));
    TEST_ASSERT_TRUE(TypeConversions::ConvertToNodeInfo(node, nullptr, nullptr).snr_unavailable);
}

static void test_flrc_pendingSelectionPreservesLatestAppliedLoraReachability(void)
{
    ConfigurationRadio radio;
    config.lora = baselineLora();
    config.lora.region = meshtastic_Config_LoRaConfig_RegionCode_US;
    config.lora.override_frequency = 915.0f;
    RadioMode::initialize(config.lora);
    TEST_ASSERT_TRUE(radio.reconfigure());
    db->refreshCommittedLoraSlot();
    const uint16_t bootSlot = db->committedLoraSlot();
    db->updateFrom(rxPacket(0x1111));

    config.lora.modem_preset = meshtastic_Config_LoRaConfig_ModemPreset_SHORT_FAST;
    config.lora.channel_num = 10;
    config.lora.override_frequency = 916.0f;
    TEST_ASSERT_TRUE(radio.reconfigure());
    db->refreshCommittedLoraSlot();
    const uint16_t latestAppliedSlot = db->committedLoraSlot();
    TEST_ASSERT_NOT_EQUAL_UINT16(bootSlot, latestAppliedSlot);
    db->updateFrom(rxPacket(0x2222));
    TEST_ASSERT_FALSE(heard(0x1111));
    TEST_ASSERT_TRUE(heard(0x2222));

    config.lora.has_radio_mode = true;
    config.lora.radio_mode = meshtastic_Config_LoRaConfig_RadioMode_FLRC;
    db->refreshCommittedLoraSlot();
    TEST_ASSERT_TRUE(RadioMode::status(config.lora).restart_pending);
    TEST_ASSERT_FALSE(RadioMode::isFlrc());
    TEST_ASSERT_EQUAL_UINT16(latestAppliedSlot, db->committedLoraSlot());
    db->updateFrom(rxPacket(0x3333));
    TEST_ASSERT_EQUAL_UINT16(latestAppliedSlot, nodeInfoLiteHeardSlot(db->getMeshNode(0x3333)));
    TEST_ASSERT_TRUE(heard(0x2222));
    TEST_ASSERT_TRUE(heard(0x3333));
    TEST_ASSERT_FALSE(heard(0x1111));
}

// ---------- storing the slot on a hear -------------------------------------------------------

static void test_hear_rfHearMarksNodeOnCurrentSlot(void)
{
    db->updateFrom(rxPacket(0x4444));
    TEST_ASSERT_TRUE(heard(0x4444));
}

// A gateway rebroadcast is TRANSPORT_LORA + via_mqtt: we heard the gateway, not the node.
static void test_hear_mqttRelayDoesNotMark(void)
{
    meshtastic_MeshPacket mp = rxPacket(0x5555);
    mp.via_mqtt = true;
    db->updateFrom(mp);
    TEST_ASSERT_NOT_NULL(db->getMeshNode(0x5555)); // admitted...
    TEST_ASSERT_FALSE(heard(0x5555));              // ...but not as an RF hear on this slot
}

static void test_hear_mqttTransportDoesNotMark(void)
{
    meshtastic_MeshPacket mp = rxPacket(0x6666);
    mp.transport_mechanism = meshtastic_MeshPacket_TransportMechanism_TRANSPORT_MQTT;
    db->updateFrom(mp);
    TEST_ASSERT_NOT_NULL(db->getMeshNode(0x6666));
    TEST_ASSERT_FALSE(heard(0x6666));
}

// The mark is about the radio, not the clock: an RF hear counts before the clock is trusted.
static void test_hear_countsWithUntrustedClock(void)
{
    meshtastic_MeshPacket mp = rxPacket(0x7777);
    mp.has_rx_time = false;
    db->updateFrom(mp);
    TEST_ASSERT_TRUE(heard(0x7777));
}

// A pre-feature record has an all-zero bitfield. Without the has-RF-hear bit gating it, stored slot 0
// would collide with whatever the radio happens to be on and mark every legacy node heard.
static void test_hear_legacyRecordReadsUnheard(void)
{
    db->push(0xAAAA);
    TEST_ASSERT_FALSE(heard(0xAAAA));
}

// ---------- the scan: rolling through presets and back ---------------------------------------

// The regression this design exists for. A client scanning A->B->C->A must leave A's marks intact:
// the hops sweep nothing, and coming home makes the stored slots match again on their own.
static void test_scan_roundTripRestoresTheMark(void)
{
    db->updateFrom(rxPacket(0x1111)); // heard on A
    TEST_ASSERT_TRUE(heard(0x1111));

    commitPreset(meshtastic_Config_LoRaConfig_ModemPreset_SHORT_FAST); // hop to B
    TEST_ASSERT_FALSE(heard(0x1111));                                  // unreachable while parked on B

    commitPreset(meshtastic_Config_LoRaConfig_ModemPreset_MEDIUM_FAST); // hop to C
    TEST_ASSERT_FALSE(heard(0x1111));

    commitHome();
    TEST_ASSERT_TRUE(heard(0x1111));
}

// The other direction: a node heard only while parked on B must not read as reachable back on A.
static void test_scan_nodeHeardOnOtherSlotStaysUnheardAtHome(void)
{
    commitPreset(meshtastic_Config_LoRaConfig_ModemPreset_SHORT_FAST);
    db->updateFrom(rxPacket(0x2222)); // a foreign node, heard on B
    TEST_ASSERT_TRUE(heard(0x2222));

    commitHome();
    TEST_ASSERT_FALSE(heard(0x2222));
}

// Re-reading the committed slot is not a sweep: it must never touch a node's stored bitfield, which
// is what keeps a scan off the flash and makes the round trip above possible at all.
static void test_scan_refreshWritesNoNode(void)
{
    db->updateFrom(rxPacket(0x3333));
    const uint32_t before = db->getMeshNode(0x3333)->bitfield;

    commitPreset(meshtastic_Config_LoRaConfig_ModemPreset_SHORT_FAST);

    TEST_ASSERT_EQUAL_UINT32(before, db->getMeshNode(0x3333)->bitfield);
}

// ---------- transient switch (a beacon keyed up on another preset) ---------------------------

// MeshBeaconModule rewrites config.lora for a beacon TX and restores it. The committed slot is pinned
// across that window, so the whole node list does not blink to unheard while we key up elsewhere.
static void test_transient_committedSlotIsPinned(void)
{
    db->updateFrom(rxPacket(0x1111));
    const uint16_t home = db->committedLoraSlot();

    db->setLoraSlotTransient(true);
    commitPreset(meshtastic_Config_LoRaConfig_ModemPreset_SHORT_FAST);

    TEST_ASSERT_EQUAL_UINT16(home, db->committedLoraSlot());
    TEST_ASSERT_TRUE(heard(0x1111));
}

// A hear while parked on the beacon's preset belongs to that preset, so it stops matching at home.
static void test_transient_hearIsStampedWithTheLiveSlot(void)
{
    db->setLoraSlotTransient(true);
    config.lora.modem_preset = meshtastic_Config_LoRaConfig_ModemPreset_SHORT_FAST;
    db->updateFrom(rxPacket(0x8888));

    db->setLoraSlotTransient(false);
    commitHome();

    TEST_ASSERT_NOT_NULL(db->getMeshNode(0x8888)); // still admitted
    TEST_ASSERT_FALSE(heard(0x8888));
}

NDB_TEST_ENTRY void setup()
{
    initializeTestEnvironment();
    db = new NodeDBTestShim();
    nodeDB = db;
    savedLora = config.lora;

    UNITY_BEGIN();
    RUN_TEST(test_fingerprint_identicalConfigMatches);
    RUN_TEST(test_fingerprint_regionIsASlotChange);
    RUN_TEST(test_fingerprint_presetIsASlotChange);
    RUN_TEST(test_fingerprint_channelNumChangesSlot);
    RUN_TEST(test_fingerprint_overrideFrequencyIsASlotChange);
    RUN_TEST(test_fingerprint_primaryChannelRenameIsASlotChange);
    RUN_TEST(test_fingerprint_usePresetToggleIsASlotChange);
    RUN_TEST(test_fingerprint_dormantModemFieldsIgnoredWhenUsingPreset);
    RUN_TEST(test_fingerprint_dormantPresetIgnoredWhenNotUsingPreset);
    RUN_TEST(test_fingerprint_customModemFieldsCountWhenNotUsingPreset);
    RUN_TEST(test_flrc_profileIgnoresRetainedLoraTuning);
    RUN_TEST(test_flrc_savedSelectionDoesNotMoveActiveReachability);
    RUN_TEST(test_flrc_receiveDoesNotInventSnr);
    RUN_TEST(test_flrc_pendingSelectionPreservesLatestAppliedLoraReachability);
    RUN_TEST(test_hear_rfHearMarksNodeOnCurrentSlot);
    RUN_TEST(test_hear_mqttRelayDoesNotMark);
    RUN_TEST(test_hear_mqttTransportDoesNotMark);
    RUN_TEST(test_hear_countsWithUntrustedClock);
    RUN_TEST(test_hear_legacyRecordReadsUnheard);
    RUN_TEST(test_scan_roundTripRestoresTheMark);
    RUN_TEST(test_scan_nodeHeardOnOtherSlotStaysUnheardAtHome);
    RUN_TEST(test_scan_refreshWritesNoNode);
    RUN_TEST(test_transient_committedSlotIsPinned);
    RUN_TEST(test_transient_hearIsStampedWithTheLiveSlot);
    exit(UNITY_END());
}
NDB_TEST_ENTRY void loop() {}
