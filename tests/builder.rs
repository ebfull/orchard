#![cfg(feature = "circuit")]

use incrementalmerkletree::{Hashable, Marking, Retention};
use orchard::{
    builder::{Builder, BundleType},
    bundle::{Authorized, BatchValidator, Flags},
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, PreparedIncomingViewingKey, Scope, SpendAuthorizingKey, SpendingKey},
    note::ExtractedNoteCommitment,
    note_encryption::OrchardDomain,
    tree::MerkleHashOrchard,
    value::NoteValue,
    Bundle,
};
use rand::rngs::OsRng;
use shardtree::{store::memory::MemoryShardStore, ShardTree};
use zcash_note_encryption::try_note_decryption;

fn verify_bundle(bundle: &Bundle<Authorized, i64>, vk: &VerifyingKey) {
    assert!(matches!(bundle.verify_proof(vk), Ok(())));
    let sighash: [u8; 32] = bundle.commitment().into();
    let bvk = bundle.binding_validating_key();
    for action in bundle.actions() {
        assert_eq!(action.rk().verify(&sighash, action.authorization()), Ok(()));
    }
    assert_eq!(
        bvk.verify(&sighash, bundle.authorization().binding_signature()),
        Ok(())
    );
}

#[test]
fn bundle_chain() {
    let mut rng = OsRng;
    let pk = ProvingKey::build();
    let vk = VerifyingKey::build();

    let sk = SpendingKey::from_bytes([0; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);

    // Create a shielding bundle.
    let shielding_bundle: Bundle<_, i64> = {
        // Use the empty tree.
        let anchor = MerkleHashOrchard::empty_root(32.into()).into();

        let mut builder = Builder::new(
            BundleType::Transactional {
                flags: Flags::SPENDS_DISABLED,
                bundle_required: false,
            },
            anchor,
        );
        let note_value = NoteValue::from_raw(5000);
        assert_eq!(
            builder.add_output(None, recipient, note_value, [0u8; 512]),
            Ok(())
        );
        let (unauthorized, bundle_meta) = builder.build(&mut rng).unwrap().unwrap();

        assert_eq!(
            unauthorized
                .decrypt_output_with_key(
                    bundle_meta
                        .output_action_index(0)
                        .expect("Output 0 can be found"),
                    &fvk.to_ivk(Scope::External)
                )
                .map(|(note, _, _)| note.value()),
            Some(note_value)
        );

        let sighash = unauthorized.commitment().into();
        let proven = unauthorized.create_proof(&pk, &mut rng).unwrap();
        proven.apply_signatures(rng, sighash, &[]).unwrap()
    };

    // Verify the shielding bundle.
    verify_bundle(&shielding_bundle, &vk);

    // Create a shielded bundle spending the previous output.
    let shielded_bundle: Bundle<_, i64> = {
        let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
        let (note, _, _) = shielding_bundle
            .actions()
            .iter()
            .find_map(|action| {
                let domain = OrchardDomain::for_action(action);
                try_note_decryption(&domain, &ivk, action)
            })
            .unwrap();

        // Use the tree with a single leaf.
        let cmx: ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
            ShardTree::new(MemoryShardStore::empty(), 100);
        tree.append(
            leaf,
            Retention::Checkpoint {
                id: 0,
                marking: Marking::Marked,
            },
        )
        .unwrap();
        let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
        let position = tree.max_leaf_position(None).unwrap().unwrap();
        let merkle_path = tree
            .witness_at_checkpoint_id(position, &0)
            .unwrap()
            .unwrap();
        assert_eq!(root, merkle_path.root(MerkleHashOrchard::from_cmx(&cmx)));

        let mut builder = Builder::new(BundleType::DEFAULT, root.into());
        assert_eq!(builder.add_spend(fvk, note, merkle_path.into()), Ok(()));
        assert_eq!(
            builder.add_output(None, recipient, NoteValue::from_raw(5000), [0u8; 512]),
            Ok(())
        );
        let (unauthorized, _) = builder.build(&mut rng).unwrap().unwrap();
        let sighash = unauthorized.commitment().into();
        let proven = unauthorized.create_proof(&pk, &mut rng).unwrap();
        proven
            .apply_signatures(rng, sighash, &[SpendAuthorizingKey::from(&sk)])
            .unwrap()
    };

    // Verify the shielded bundle.
    verify_bundle(&shielded_bundle, &vk);
}

// A bundle built with the circuit version set to `InsecurePreNu6_2` produces a proof against
// the historical (insecure) circuit, which verifies under the insecure verifying key but not
// the fixed one. This is the path that lets tests reproduce pre-NU6.2 proofs.
#[test]
fn builder_builds_for_insecure_circuit_version() {
    let mut rng = OsRng;
    let insecure_pk = ProvingKey::build_for_version(OrchardCircuitVersion::InsecurePreNu6_2);
    let insecure_vk = VerifyingKey::build_for_version(OrchardCircuitVersion::InsecurePreNu6_2);
    let fixed_vk = VerifyingKey::build();

    let sk = SpendingKey::from_bytes([0; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);

    let anchor = MerkleHashOrchard::empty_root(32.into()).into();
    let mut builder = Builder::new_for_version(
        BundleType::Transactional {
            flags: Flags::SPENDS_DISABLED,
            bundle_required: false,
        },
        anchor,
        OrchardCircuitVersion::InsecurePreNu6_2,
    );
    assert_eq!(
        builder.add_output(None, recipient, NoteValue::from_raw(5000), [0u8; 512]),
        Ok(())
    );

    let (unauthorized, _) = builder.build::<i64>(&mut rng).unwrap().unwrap();
    let sighash: [u8; 32] = unauthorized.commitment().into();
    let proven = unauthorized.create_proof(&insecure_pk, &mut rng).unwrap();
    let bundle = proven.apply_signatures(rng, sighash, &[]).unwrap();

    assert!(matches!(bundle.verify_proof(&insecure_vk), Ok(())));
    assert!(bundle.verify_proof(&fixed_vk).is_err());
}

// An Ironwood bundle chain: an ordinary (cross-address-permitting) shielding bundle,
// followed by a bundle that disables cross-address transfers, withdrawing part of the
// shielded value and retaining the rest as wallet-controlled change.
#[test]
fn ironwood_bundle_chain() {
    let mut rng = OsRng;
    let pk = ProvingKey::build_for_version(OrchardCircuitVersion::Ironwood);
    let vk = VerifyingKey::build_for_version(OrchardCircuitVersion::Ironwood);
    let fixed_vk = VerifyingKey::build();

    let sk = SpendingKey::from_bytes([0; 32]).unwrap();
    let fvk = FullViewingKey::from(&sk);
    let recipient = fvk.address_at(0u32, Scope::External);

    // Create an ordinary Ironwood shielding bundle: with cross-address transfers
    // permitted, its flags are identical to a pre-Ironwood bundle's, and only the
    // explicitly selected circuit version distinguishes it.
    let shielding_bundle: Bundle<_, i64> = {
        let anchor = MerkleHashOrchard::empty_root(32.into()).into();

        let mut builder = Builder::new_for_version(
            BundleType::Transactional {
                flags: Flags::SPENDS_DISABLED,
                bundle_required: false,
            },
            anchor,
            OrchardCircuitVersion::Ironwood,
        );
        assert_eq!(
            builder.add_output(None, recipient, NoteValue::from_raw(5000), [0u8; 512]),
            Ok(())
        );
        let (unauthorized, _) = builder.build(&mut rng).unwrap().unwrap();
        let sighash = unauthorized.commitment().into();
        let proven = unauthorized.create_proof(&pk, &mut rng).unwrap();
        proven.apply_signatures(rng, sighash, &[]).unwrap()
    };

    verify_bundle(&shielding_bundle, &vk);
    // An Ironwood proof is bound to the Ironwood verifying key.
    assert!(shielding_bundle.verify_proof(&fixed_vk).is_err());

    // Create a bundle that disables cross-address transfers, spending the previous
    // output: 2000 zatoshis are withdrawn through the value balance, and 3000 are
    // retained as change at the wallet's internal address.
    let change_addr = fvk.address_at(0u32, Scope::Internal);
    let restricted_bundle: Bundle<_, i64> = {
        let ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
        let (note, _, _) = shielding_bundle
            .actions()
            .iter()
            .find_map(|action| {
                let domain = OrchardDomain::for_action(action);
                try_note_decryption(&domain, &ivk, action)
            })
            .unwrap();

        // Use the tree with a single leaf.
        let cmx: ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut tree: ShardTree<MemoryShardStore<MerkleHashOrchard, u32>, 32, 16> =
            ShardTree::new(MemoryShardStore::empty(), 100);
        tree.append(
            leaf,
            Retention::Checkpoint {
                id: 0,
                marking: Marking::Marked,
            },
        )
        .unwrap();
        let root = tree.root_at_checkpoint_id(&0).unwrap().unwrap();
        let position = tree.max_leaf_position(None).unwrap().unwrap();
        let merkle_path = tree
            .witness_at_checkpoint_id(position, &0)
            .unwrap()
            .unwrap();

        let mut builder = Builder::new_for_version(
            BundleType::Transactional {
                flags: Flags::CROSS_ADDRESS_DISABLED,
                bundle_required: false,
            },
            root.into(),
            OrchardCircuitVersion::Ironwood,
        );
        assert_eq!(
            builder.add_spend(fvk.clone(), note, merkle_path.into()),
            Ok(())
        );
        assert_eq!(
            builder.add_change_output(
                fvk.clone(),
                Some(fvk.to_ovk(Scope::Internal)),
                change_addr,
                NoteValue::from_raw(3000),
                [0u8; 512],
            ),
            Ok(())
        );
        let (unauthorized, bundle_meta) = builder.build(&mut rng).unwrap().unwrap();

        // The spend and the change output occupy one action each, and the change
        // decrypts with the internal incoming viewing key at its metadata index.
        assert_eq!(unauthorized.actions().len(), 2);
        assert_ne!(
            bundle_meta.spend_action_index(0),
            bundle_meta.output_action_index(0)
        );
        assert_eq!(
            unauthorized
                .decrypt_output_with_key(
                    bundle_meta
                        .output_action_index(0)
                        .expect("Output 0 can be found"),
                    &fvk.to_ivk(Scope::Internal)
                )
                .map(|(note, recipient, _)| (note.value(), recipient)),
            Some((NoteValue::from_raw(3000), change_addr))
        );

        let sighash = unauthorized.commitment().into();
        let proven = unauthorized.create_proof(&pk, &mut rng).unwrap();
        // A single spend authorizing key covers both the real spend and the fabricated
        // wallet-controlled change spend.
        proven
            .apply_signatures(rng, sighash, &[SpendAuthorizingKey::from(&sk)])
            .unwrap()
    };

    assert_eq!(restricted_bundle.value_balance(), &2000);
    verify_bundle(&restricted_bundle, &vk);

    // A restricted statement is rejected outright under a key whose circuit version
    // does not constrain the disableCrossAddress flag.
    assert!(restricted_bundle.verify_proof(&fixed_vk).is_err());

    // The same holds for batch validation.
    let mut validator = BatchValidator::new();
    validator.add_bundle(&restricted_bundle, restricted_bundle.commitment().into());
    assert!(validator.validate(&vk, rng));

    let mut validator = BatchValidator::new();
    validator.add_bundle(&restricted_bundle, restricted_bundle.commitment().into());
    assert!(!validator.validate(&fixed_vk, rng));
}
