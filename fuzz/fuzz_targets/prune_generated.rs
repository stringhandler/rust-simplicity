// SPDX-License-Identifier: CC0-1.0

#![cfg_attr(fuzzing, no_main)]

#[cfg(any(fuzzing, test))]
fn do_test(data: &[u8]) {
    use libfuzzer_sys::arbitrary::Unstructured;
    use simplicity::ffi::tests::{ffi::SimplicityErr, run_program, TestUpTo};
    use simplicity::hashes::sha256::Midstate;
    use simplicity::jet::{elements::ElementsEnv, Elements};
    use simplicity::{BitIter, BitMachine, RedeemNode};

    let program = match simplicity_fuzz::generate_program(&mut Unstructured::new(data)) {
        Ok(program) => program,
        Err(_) => return,
    };
    let env = ElementsEnv::dummy();
    let mut mac = match BitMachine::for_program(&program) {
        Ok(mac) => mac,
        Err(_) => return,
    };
    mac.exec(&program, &env)
        .expect("generated programs contain nothing that fails");

    let pruned = program
        .prune(&env)
        .expect("pruning succeeds when execution does");
    assert_eq!(pruned.cmr(), program.cmr(), "pruning should keep the CMR");
    BitMachine::for_program(&pruned)
        .expect("the pruned program is no larger")
        .exec(&pruned, &env)
        .expect("the pruned program should run");

    // A decoder infers the types of the pruned program from its encoding, so it
    // must infer the types that pruning did to read the witness data back.
    let (prog, wit) = pruned.to_vec_with_witness();
    let decoded =
        RedeemNode::decode::<_, _, Elements>(BitIter::from(&prog[..]), BitIter::from(&wit[..]))
            .expect("the pruned program should decode");
    assert_eq!(
        decoded.ihr(),
        pruned.ihr(),
        "the decoder should infer the types that pruning did"
    );
    assert_eq!(decoded.to_vec_with_witness(), (prog.clone(), wit.clone()));

    // libsimplicity, the consensus implementation, accepts the pruned program
    // and computes the same roots.
    let c_pruned = run_program(&prog, &wit, TestUpTo::Everything, None, None)
        .expect("libsimplicity should decode the pruned program");
    assert_eq!(
        c_pruned.eval_result,
        SimplicityErr::NoError,
        "libsimplicity should accept the pruned program"
    );
    assert_eq!(
        &Midstate::from(c_pruned.cmr).to_parts().0,
        pruned.cmr().as_ref()
    );
    assert_eq!(
        &Midstate::from(c_pruned.amr).to_parts().0,
        pruned.amr().as_ref()
    );
    assert_eq!(
        &Midstate::from(c_pruned.ihr).to_parts().0,
        pruned.ihr().as_ref()
    );

    // libsimplicity rejects the unpruned program for its unexecuted branches
    // exactly when pruning hid a branch, so both agree on what was executed.
    let unpruned = program.to_vec_with_witness();
    let c_unpruned = run_program(&unpruned.0, &unpruned.1, TestUpTo::Everything, None, None)
        .expect("libsimplicity should decode the unpruned program");
    let expected = if unpruned == (prog, wit) {
        SimplicityErr::NoError
    } else {
        SimplicityErr::AntiDoS
    };
    assert_eq!(
        c_unpruned.eval_result, expected,
        "libsimplicity should reject the unpruned program exactly when pruning changed it"
    );
}

#[cfg(fuzzing)]
libfuzzer_sys::fuzz_target!(|data| do_test(data));

#[cfg(not(fuzzing))]
fn main() {}

#[cfg(test)]
mod tests {
    #[test]
    fn pseudorandom_inputs() {
        for data in simplicity_fuzz::pseudorandom_inputs(1000) {
            super::do_test(&data);
        }
    }
}
