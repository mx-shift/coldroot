//! The real ceremonies against the YubiHSM mock: init on one device, drill on
//! another. The ceremony crate's own tests cover the share handling; this one
//! proves the wrapped blobs the YubiHSM produces round-trip through a state.

use std::collections::VecDeque;

use coldroot_ceremony::{
    Aborted, Console, Participant, ShareInput, drill,
    init::{self, InitConfig, KeySpec},
};
use coldroot_core::{shares::KeyShare, transcript::ParticipantId};
use coldroot_hsm::YubiHsm;
use yubihsm::Connector;

#[derive(Default)]
struct Scripted {
    discs: Vec<String>,
    to_present: VecDeque<(ParticipantId, ShareInput)>,
}

impl Console for Scripted {
    fn notice(&mut self, _text: &str) {}

    fn confirm(&mut self, _prompt: &str) -> Result<ParticipantId, Aborted> {
        Ok(0)
    }

    fn issue_share(&mut self, share: &KeyShare) -> Result<ParticipantId, Aborted> {
        self.discs.push(share.to_json().to_string());
        Ok(share.index())
    }

    fn collect_share(&mut self, _generation: u32) -> Result<(ParticipantId, ShareInput), Aborted> {
        self.to_present.pop_front().ok_or(Aborted)
    }
}

#[test]
fn init_then_drill_on_the_mock() {
    let people = || {
        ["Operator", "Ana", "Bo"]
            .iter()
            .map(|name| Participant {
                name: name.to_string(),
            })
            .collect::<Vec<_>>()
    };
    let config = InitConfig {
        organization: "example.org".into(),
        public_anchor: None,
        participants: people(),
        threshold: 2,
        limit: 2,
        keys: vec![KeySpec {
            id: 0x100,
            label: "root-x509".into(),
        }],
    };
    let mut console = Scripted::default();
    let mut first = YubiHsm::open(Connector::mockhsm()).unwrap();
    let init = init::run(&config, &mut first, &mut console).unwrap();

    console.to_present = VecDeque::from([
        (1, ShareInput::Disc(console.discs[0].clone())),
        (2, ShareInput::Disc(console.discs[1].clone())),
    ]);
    let mut second = YubiHsm::open(Connector::mockhsm()).unwrap();
    let drill = drill::run(&init.state, people(), &mut second, &mut console).unwrap();
    assert_eq!(drill.state.keys, init.state.keys);
    assert_ne!(drill.state.transcript_head, init.state.transcript_head);
}
