use nix::sched::{
    sched_getaffinity, sched_getparam, sched_getscheduler, sched_setaffinity, sched_setscheduler,
    CpuSet, SchedParam, SchedPolicy, SchedType,
};
use nix::unistd::Pid;

#[test]
fn test_sched_affinity() {
    // If pid is zero, then the mask of the calling process is returned.
    let initial_affinity = sched_getaffinity(Pid::from_raw(0)).unwrap();
    let mut at_least_one_cpu = false;
    let mut last_valid_cpu = 0;
    for field in 0..CpuSet::count() {
        if initial_affinity.is_set(field).unwrap() {
            at_least_one_cpu = true;
            last_valid_cpu = field;
        }
    }
    assert!(at_least_one_cpu);

    // Now restrict the running CPU
    let mut new_affinity = CpuSet::new();
    new_affinity.set(last_valid_cpu).unwrap();
    sched_setaffinity(Pid::from_raw(0), &new_affinity).unwrap();

    // And now re-check the affinity which should be only the one we set.
    let updated_affinity = sched_getaffinity(Pid::from_raw(0)).unwrap();
    for field in 0..CpuSet::count() {
        // Should be set only for the CPU we set previously
        assert_eq!(updated_affinity.is_set(field).unwrap(), field==last_valid_cpu)
    }

    // Finally, reset the initial CPU set
    sched_setaffinity(Pid::from_raw(0), &initial_affinity).unwrap();
}

#[test]
#[cfg(not(target_env = "musl"))]
fn test_sched_scheduler() {
    let initial_scheduler = sched_getscheduler(None).unwrap();

    // Pick a scheduler other than the current one
    let desired_scheduler = match initial_scheduler.sched_type {
        #[cfg(target_os = "android")]
        SchedType::SCHED_BATCH => SchedType::SCHED_NORMAL,
        #[cfg(target_os = "linux")]
        SchedType::SCHED_BATCH => SchedType::SCHED_OTHER,
        _ => SchedType::SCHED_BATCH,
    };
    sched_setscheduler(
        None,
        SchedPolicy::new(desired_scheduler),
        SchedParam::default(),
    )
    .unwrap();

    // Check that the scheduler was changed.
    assert!(sched_getscheduler(None).unwrap().sched_type == desired_scheduler);

    // Restore original scheduler
    sched_setscheduler(None, initial_scheduler, SchedParam::default()).unwrap();
}

#[test]
#[cfg(not(target_env = "musl"))]
fn test_sched_getscheduler_none_is_pid_zero() {
    let none_scheduler = sched_getscheduler(None).unwrap();
    let pid_zero_scheduler = sched_getscheduler(Some(Pid::from_raw(0))).unwrap();

    assert_eq!(none_scheduler, pid_zero_scheduler);
}

#[test]
#[cfg(not(target_env = "musl"))]
fn test_sched_getparam_none_is_pid_zero() {
    let none_param = sched_getparam(None).unwrap();
    let pid_zero_param = sched_getparam(Some(Pid::from_raw(0))).unwrap();

    assert_eq!(none_param, pid_zero_param);
}
