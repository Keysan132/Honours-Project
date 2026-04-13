from roc.simulator import init_fleet, set_attack, gen_network_event, gen_telemetry


def test_attack_sets_and_expires():
    fleet = init_fleet(n=1)
    vid = list(fleet.keys())[0]
    set_attack(fleet, vid, "DOS", duration_s=1)
    assert fleet[vid]["attack_mode"] == "DOS"


def test_generators_return_objects():
    fleet = init_fleet(n=1)
    vid = list(fleet.keys())[0]
    tel = gen_telemetry(fleet, vid, 1.0)
    net = gen_network_event(fleet, vid)
    assert tel.vessel_id == vid
    assert net.vessel_id == vid