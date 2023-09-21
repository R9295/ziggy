use crate::*;
use anyhow::{anyhow, Context, Result};
use console::{style, Term};
use glob::glob;
use std::{
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use strip_ansi_escapes::strip_str;

/// Main logic for managing fuzzers and the fuzzing process in ziggy.

/// ## Initial minimization logic

/// When launching fuzzers, if initial corpora exist, they are merged together and we minimize it
/// with both AFL++ and Honggfuzz.
/// ```text
/// # bash pseudocode
/// cp all_afl_corpora/* corpus_shared/* corpus_tmp/
/// # run afl++ minimization
/// afl++_minimization -i corpus_tmp -o corpus_minimized
/// # in parallel, run honggfuzz minimization
/// honggfuzz_minimization -i corpus_tmp -o corpus_minimized
/// rm -rf corpus_shared corpus_tmp
/// mv corpus_minimized corpus_shared
/// afl++ -i corpus_shared -o all_afl_corpora &
///   honggfuzz -i corpus_shared -o corpus_shared
/// ```
/// The `all_afl_corpora` directory corresponds to the `output/target_name/afl/**/queue/` directories.

impl Fuzz {
    pub fn corpus_shared(&self) -> String {
        self.corpus
            .display()
            .to_string()
            .replace("{target_name}", &self.target)
    }

    pub fn corpus_tmp(&self) -> String {
        format!("./output/{}/corpus_tmp/", self.target)
    }

    pub fn corpus_minimized(&self) -> String {
        format!("./output/{}/corpus_minimized/", self.target)
    }

    // Manages the continuous running of fuzzers
    pub fn fuzz(&mut self) -> Result<(), anyhow::Error> {
        let build = Build {
            no_afl: self.no_afl,
            no_honggfuzz: self.no_honggfuzz,
        };
        build.build().context("Failed to build the fuzzers")?;

        info!("Running fuzzer");

        self.target = find_target(&self.target).context("⚠️  couldn't find target when fuzzing")?;

        let time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

        let crash_dir = format!("./output/{}/crashes/{}/", self.target, time);
        let crash_path = Path::new(&crash_dir);
        fs::create_dir_all(crash_path)?;

        let _ = process::Command::new("mkdir")
            .args(["-p", &format!("./output/{}/logs/", self.target)])
            .stderr(process::Stdio::piped())
            .spawn()?
            .wait()?;

        if Path::new(&self.corpus_shared()).exists() {
            if self.perform_initial_minimization {
                fs::create_dir_all(&self.corpus_tmp())
                    .context("Could not create temporary corpus")?;
                self.copy_corpora()
                    .context("Could not move all seeds to temporary corpus")?;
                let _ = fs::remove_dir_all(&self.corpus_minimized());
                self.run_minimization()
                    .context("Failure while minimizing")?;
                fs::remove_dir_all(&self.corpus_shared())
                    .context("Could not remove shared corpus")?;
                fs::rename(&self.corpus_minimized(), &self.corpus_shared())
                    .context("Could not move minimized corpus over")?;
                fs::remove_dir_all(&self.corpus_tmp())
                    .context("Could not remove temporary corpus")?;
            }
        } else {
            let _ = process::Command::new("mkdir")
                .args(["-p", &self.corpus_shared()])
                .stderr(process::Stdio::piped())
                .spawn()?
                .wait()?;

            // We create an initial corpus file, so that AFL++ starts-up properly
            let mut initial_corpus = File::create(self.corpus_shared() + "/init")?;
            writeln!(
                &mut initial_corpus,
                "00000000000000000000********0000########111111111111111111111111"
            )?;
            drop(initial_corpus);
        }

        // We create an initial corpus file, so that AFL++ starts-up properly if corpus is empty
        let mut initial_corpus = File::create(self.corpus_shared() + "/init")?;
        writeln!(&mut initial_corpus, "00000000")?;
        drop(initial_corpus);

        let mut processes = self.spawn_new_fuzzers(false)?;

        loop {
            let sleep_duration = Duration::from_millis(1000);
            thread::sleep(sleep_duration);

            self.print_stats();

            if let Ok(afl_log) =
                fs::read_to_string(format!("./output/{}/logs/afl.log", self.target))
            {
                if afl_log.contains("echo core >/proc/sys/kernel/core_pattern") {
                    stop_fuzzers(&mut processes)?;
                    eprintln!("AFL++ needs you to run the following command before it can start fuzzing:\n");
                    eprintln!("    echo core >/proc/sys/kernel/core_pattern\n");
                    return Ok(());
                }
                if afl_log.contains("cd /sys/devices/system/cpu") {
                    stop_fuzzers(&mut processes)?;
                    eprintln!("AFL++ needs you to run the following commands before it can start fuzzing:\n");
                    eprintln!("    cd /sys/devices/system/cpu");
                    eprintln!("    echo performance | tee cpu*/cpufreq/scaling_governor\n");
                    return Ok(());
                }
            }

            // We check AFL++ and Honggfuzz's outputs for crash files and copy them over to
            // our own crashes directory
            let crash_dirs = glob(&format!("./output/{}/afl/*/crashes", self.target))
                .map_err(|_| anyhow!("Failed to read crashes glob pattern"))?
                .flatten()
                .chain(vec![format!(
                    "./output/{}/honggfuzz/{}",
                    self.target, self.target
                )
                .into()]);

            for crash_dir in crash_dirs {
                if let Ok(crashes) = fs::read_dir(crash_dir) {
                    for crash_input in crashes.flatten() {
                        let file_name = crash_input.file_name();
                        let to_path = crash_path.join(&file_name);
                        if to_path.exists()
                            || ["", "README.txt", "HONGGFUZZ.REPORT.TXT", "input"]
                                .contains(&file_name.to_str().unwrap_or_default())
                        {
                            continue;
                        }
                        fs::copy(crash_input.path(), to_path)?;
                    }
                }
            }

            if processes
                .iter_mut()
                .all(|p| p.try_wait().unwrap_or(None).is_some())
            {
                stop_fuzzers(&mut processes)?;
                warn!("Fuzzers stopped, check for errors!");
                return Ok(());
            }
        }
    }

    // Spawns new fuzzers
    pub fn spawn_new_fuzzers(
        &self,
        only_honggfuzz: bool,
    ) -> Result<Vec<process::Child>, anyhow::Error> {
        // No fuzzers for you
        if self.no_afl && self.no_honggfuzz {
            return Err(anyhow!("Pick at least one fuzzer"));
        }

        info!("Spawning new fuzzers");

        let mut fuzzer_handles = vec![];

        // The cargo executable
        let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));

        let (afl_jobs, honggfuzz_jobs) = {
            if self.no_afl {
                (0, self.jobs)
            } else if self.no_honggfuzz {
                (self.jobs, 0)
            } else {
                // we assign roughly 2/3 to AFL++, 1/3 to honggfuzz, however do
                // not apply more than 4 jobs to honggfuzz
                match self.jobs {
                    1 => (1, 0),
                    2..=12 => (self.jobs - ((self.jobs + 2) / 3), (self.jobs + 2) / 3),
                    _ => (self.jobs - 4, 4),
                }
            }
        };

        if honggfuzz_jobs > 4 {
            eprintln!("Warning: running more honggfuzz jobs than 4 is not effective");
        }

        if !self.no_afl && !only_honggfuzz && afl_jobs > 0 {
            let _ = process::Command::new("mkdir")
                .args(["-p", &format!("./output/{}/afl", self.target)])
                .stderr(process::Stdio::piped())
                .spawn()?
                .wait()?;

            // https://aflplus.plus/docs/fuzzing_in_depth/#c-using-multiple-cores
            let afl_modes = [
                "explore", "fast", "coe", "lin", "quad", "exploit", "rare", "explore", "fast",
                "mmopt",
            ];

            for job_num in 0..afl_jobs {
                // We set the fuzzer name, and if it's the main or a secondary fuzzer
                let fuzzer_name = match job_num {
                    0 => String::from("-Mmainaflfuzzer"),
                    n => format!("-Ssecondaryfuzzer{n}"),
                };
                let use_shared_corpus = match job_num {
                    0 => format!("-F{}", &self.corpus_shared()),
                    _ => String::new(),
                };
                let use_initial_corpus_dir = match (&self.initial_corpus, job_num) {
                    (Some(initial_corpus), 0) => {
                        format!("-F{}", &initial_corpus.display().to_string())
                    }
                    _ => String::new(),
                };
                // 10% of secondary fuzzers have the MOpt mutator enabled
                let mopt_mutator = match job_num % 10 {
                    9 => "-L0",
                    _ => "",
                };
                // Power schedule
                let power_schedule = afl_modes
                    .get(job_num as usize % afl_modes.len())
                    .unwrap_or(&"fast");
                // Old queue cycling
                let old_queue_cycling = match job_num % 10 {
                    8 => "-Z",
                    _ => "",
                };
                // Only few instances do cmplog
                let cmplog_options = match job_num {
                    1 => "-l2a",
                    3 => "-l1",
                    14 => "-l2a",
                    22 => "-l3at",
                    _ => "-c-", // disable Cmplog, needs AFL++ 4.08a
                };
                // AFL timeout is in ms so we convert the value
                let timeout_option_afl = match self.timeout {
                    Some(t) => format!("-t{}", t * 1000),
                    None => String::new(),
                };
                let dictionary_option = match &self.dictionary {
                    Some(d) => format!("-x{}", &d.display().to_string()),
                    None => String::new(),
                };
                let mutation_option = match job_num / 5 {
                    0..=1 => "-P600",
                    2..=3 => "-Pexplore",
                    _ => "-Pexploit",
                };
                /* wait for afl crate update
                let mutation_option = match job_num / 2 {
                    0 => "-abinary",
                    _ => "-adefault",
                };
                */
                let log_destination = || match job_num {
                    0 => File::create(format!("output/{}/logs/afl.log", self.target))
                        .unwrap()
                        .into(),
                    1 => File::create(format!("output/{}/logs/afl_1.log", self.target))
                        .unwrap()
                        .into(),
                    _ => process::Stdio::null(),
                };
                let final_sync = match job_num {
                    0 => "AFL_FINAL_SYNC",
                    _ => "_DUMMY_VAR",
                };

                fuzzer_handles.push(
                    process::Command::new(cargo.clone())
                        .args(
                            [
                                "afl",
                                "fuzz",
                                &fuzzer_name,
                                &format!("-i{}", self.corpus_shared()),
                                &format!("-p{power_schedule}"),
                                &format!("-ooutput/{}/afl", self.target),
                                &format!("-g{}", self.min_length),
                                &format!("-G{}", self.max_length),
                                &use_shared_corpus,
                                // &format!("-V{}", self.minimization_timeout + SECONDS_TO_WAIT_AFTER_KILL, &use_initial_corpus_dir),
                                &use_initial_corpus_dir,
                                old_queue_cycling,
                                cmplog_options,
                                mopt_mutator,
                                mutation_option,
                                &timeout_option_afl,
                                &dictionary_option,
                                &format!("./target/afl/debug/{}", self.target),
                            ]
                            .iter()
                            .filter(|a| a != &&""),
                        )
                        .env("AFL_AUTORESUME", "1")
                        .env("AFL_TESTCACHE_SIZE", "100")
                        .env("AFL_FAST_CAL", "1")
                        .env("AFL_FORCE_UI", "1")
                        .env("AFL_IGNORE_UNKNOWN_ENVS", "1")
                        .env("AFL_CMPLOG_ONLY_NEW", "1")
                        .env("AFL_DISABLE_TRIM", "1")
                        .env("AFL_NO_WARN_INSTABILITY", "1")
                        .env("AFL_FUZZER_STATS_UPDATE_INTERVAL", "10")
                        .env("AFL_IMPORT_FIRST", "1")
                        .env(final_sync, "1") // upcoming in v4.09c
                        .env("AFL_IGNORE_SEED_PROBLEMS", "1") // upcoming in v4.09c
                        .stdout(log_destination())
                        .stderr(log_destination())
                        .spawn()?,
                )
            }
            eprintln!("{} afl           ", style("    Launched").green().bold());
        }

        if !self.no_honggfuzz && honggfuzz_jobs > 0 {
            let dictionary_option = match &self.dictionary {
                Some(d) => format!("-w{}", &d.display().to_string()),
                None => String::new(),
            };

            let timeout_option = match self.timeout {
                Some(t) => format!("-t{t}"),
                None => String::new(),
            };

            // The `script` invocation is a trick to get the correct TTY output for honggfuzz
            fuzzer_handles.push(
                process::Command::new("script")
                    .args([
                        "--flush",
                        "--quiet",
                        "-c",
                        &format!("{} hfuzz run {}", cargo, &self.target),
                        "/dev/null",
                    ])
                    .env("HFUZZ_BUILD_ARGS", "--features=ziggy/honggfuzz")
                    .env("CARGO_TARGET_DIR", "./target/honggfuzz")
                    .env(
                        "HFUZZ_WORKSPACE",
                        format!("./output/{}/honggfuzz", self.target),
                    )
                    .env(
                        "HFUZZ_RUN_ARGS",
                        format!(
                            "-i{} -o{} -n{honggfuzz_jobs} -F{} {timeout_option} {dictionary_option}",
                            &self.corpus_shared(),
                            &self.corpus_shared(),
                            self.max_length,
                        ),
                    )
                    .stdin(std::process::Stdio::null())
                    .stderr(File::create(format!(
                        "./output/{}/logs/honggfuzz.log",
                        self.target
                    ))?)
                    .stdout(File::create(format!(
                        "./output/{}/logs/honggfuzz.log",
                        self.target
                    ))?)
                    .spawn()?,
            );
            eprintln!(
                "{} honggfuzz              ",
                style("    Launched").green().bold()
            );
        }

        eprintln!("\nSee live information by running:");
        if afl_jobs > 0 {
            eprintln!(
                "  {}",
                style(format!("tail -f ./output/{}/logs/afl.log", self.target)).bold()
            );
        }
        if afl_jobs > 1 {
            eprintln!(
                "  {}",
                style(format!("tail -f ./output/{}/logs/afl_1.log", self.target)).bold()
            );
        }
        if honggfuzz_jobs > 0 {
            eprintln!(
                "  {}",
                style(format!(
                    "tail -f ./output/{}/logs/honggfuzz.log",
                    self.target
                ))
                .bold()
            );
        }
        eprintln!("\n\n\n");
        eprintln!("   Waiting for fuzzers to");
        eprintln!("   finish executing the");
        eprintln!("   existing corpus once");
        eprintln!("\n\n");

        Ok(fuzzer_handles)
    }

    fn all_seeds(&self) -> Result<Vec<PathBuf>> {
        Ok(glob(&format!("./output/{}/afl/*/queue/*", self.target))
            .map_err(|_| anyhow!("Failed to read AFL++ queue glob pattern"))?
            .chain(
                glob(&format!("{}/*", self.corpus_shared()))
                    .map_err(|_| anyhow!("Failed to read Honggfuzz corpus glob pattern"))?,
            )
            .flatten()
            .filter(|f| f.is_file())
            .collect())
    }

    // Copy all corpora into `corpus_shared`
    pub fn copy_corpora(&self) -> Result<()> {
        self.all_seeds()?.iter().for_each(|s| {
            let _ = fs::copy(
                s.to_str().unwrap_or_default(),
                format!(
                    "{}/{}",
                    &self.corpus_tmp(),
                    s.file_name()
                        .unwrap_or_default()
                        .to_str()
                        .unwrap_or_default(),
                ),
            );
        });
        Ok(())
    }

    pub fn run_minimization(&self) -> Result<()> {
        let term = Term::stdout();

        term.write_line(&format!(
            "\n    {}",
            &style("Running minimization").magenta().bold()
        ))?;

        let input_corpus = &self.corpus_tmp();
        let output_corpus = &self.corpus_minimized();

        let old_corpus_size = fs::read_dir(input_corpus)
            .map_or(String::from("err"), |corpus| format!("{}", corpus.count()));

        let mut minimization_args = Minimize {
            target: self.target.clone(),
            input_corpus: PathBuf::from(input_corpus),
            output_corpus: PathBuf::from(output_corpus),
            jobs: self.jobs,
            engine: FuzzingEngines::All,
        };
        match minimization_args.minimize() {
            Ok(_) => {
                let new_corpus_size = fs::read_dir(output_corpus)
                    .map_or(String::from("err"), |corpus| format!("{}", corpus.count()));

                term.move_cursor_up(1)?;

                if new_corpus_size == *"err" || new_corpus_size == *"0" {
                    return Err(anyhow!("Please check the logs and make sure the right version of the fuzzers are installed"));
                } else {
                    term.write_line(&format!(
                        "{} the corpus ({} -> {} files)             \n",
                        style("    Minimized").magenta().bold(),
                        old_corpus_size,
                        new_corpus_size
                    ))?;
                }
            }
            Err(_) => {
                return Err(anyhow!("Please check the logs, this might be an oom error"));
            }
        };
        Ok(())
    }

    pub fn print_stats(&self) {
        // First step: execute afl-whatsup
        let mut afl_status = String::from("running ─");
        let mut afl_total_run_time = String::new();
        let mut afl_total_execs = String::new();
        let mut afl_instances = String::new();
        let mut afl_speed = String::new();
        let mut afl_coverage = String::new();
        let mut afl_crashes = String::new();
        let mut afl_new_finds = String::new();

        if self.no_afl {
            afl_status = String::from("disabled ")
        } else {
            let cargo = env::var("CARGO").unwrap_or_else(|_| String::from("cargo"));
            let afl_stats_process = process::Command::new(cargo)
                .args([
                    "afl",
                    "whatsup",
                    "-s",
                    &format!("output/{}/afl", self.target),
                ])
                .output();

            if let Ok(process) = afl_stats_process {
                let s = std::str::from_utf8(&process.stdout).unwrap_or_default();

                for mut line in s.split('\n') {
                    line = line.trim();
                    if let Some(total_run_time) = line.strip_prefix("Total run time : ") {
                        afl_total_run_time =
                            String::from(total_run_time.split(',').next().unwrap_or_default());
                    } else if let Some(total_execs) = line.strip_prefix("Total execs : ") {
                        afl_total_execs =
                            String::from(total_execs.split(',').next().unwrap_or_default());
                    } else if let Some(instances) = line.strip_prefix("Fuzzers alive : ") {
                        afl_instances = String::from(instances);
                    } else if let Some(speed) = line.strip_prefix("Cumulative speed : ") {
                        afl_speed = String::from(speed);
                    } else if let Some(coverage) = line.strip_prefix("Coverage reached : ") {
                        afl_coverage = String::from(coverage);
                    } else if let Some(crashes) = line.strip_prefix("Crashes saved : ") {
                        afl_crashes = String::from(crashes);
                    } else if let Some(new_finds) = line.strip_prefix("Time without finds : ") {
                        afl_new_finds = String::from(new_finds);
                    }
                }
            }
        }

        // Second step: Get stats from honggfuzz logs
        let mut hf_status = String::from("running ─");
        let mut hf_minimization_in = String::new();
        let mut hf_total_execs = String::new();
        let mut hf_threads = String::new();
        let mut hf_speed = String::new();
        let mut hf_coverage = String::new();
        let mut hf_crashes = String::new();
        let mut hf_new_finds = String::new();

        if self.no_honggfuzz || (self.jobs == 1 && !self.no_afl) {
            hf_status = String::from("disabled ");
        } else {
            let hf_stats_process = process::Command::new("tail")
                .args([
                    "-n50",
                    &format!("./output/{}/logs/honggfuzz.log", self.target),
                ])
                .output();
            if let Ok(process) = hf_stats_process {
                let s = std::str::from_utf8(&process.stdout).unwrap_or_default();
                for raw_line in s.split('\n') {
                    let stripped_line = strip_str(raw_line);
                    let line = stripped_line.trim();
                    if let Some(minimization_in) = line.strip_prefix("------------------------[ ") {
                        hf_minimization_in = String::from(
                            minimization_in.split(']').next().unwrap_or_default().trim(),
                        );
                        hf_minimization_in = String::from(
                            hf_minimization_in
                                .strip_prefix("0 days")
                                .unwrap_or(&hf_minimization_in)
                                .trim(),
                        );
                        hf_minimization_in =
                            String::from(hf_minimization_in.split(" mins").next().unwrap_or("0"))
                                + " mins";
                    } else if let Some(total_execs) = line.strip_prefix("Iterations : ") {
                        hf_total_execs =
                            String::from(total_execs.split(' ').next().unwrap_or_default());
                    } else if let Some(threads) = line.strip_prefix("Threads : ") {
                        hf_threads = String::from(threads.split(',').next().unwrap_or_default());
                    } else if let Some(speed) = line.strip_prefix("Speed : ") {
                        hf_speed = String::from(
                            speed
                                .split("[avg: ")
                                .nth(1)
                                .unwrap_or_default()
                                .strip_suffix(']')
                                .unwrap_or_default(),
                        ) + "/sec";
                    } else if let Some(coverage) = line.strip_prefix("Coverage : ") {
                        hf_coverage = String::from(
                            coverage
                                .split('[')
                                .nth(1)
                                .unwrap_or_default()
                                .split(']')
                                .next()
                                .unwrap_or_default(),
                        );
                    } else if let Some(crashes) = line.strip_prefix("Crashes : ") {
                        hf_crashes = String::from(crashes.split(' ').next().unwrap_or_default());
                    } else if let Some(new_finds) = line.strip_prefix("Cov Update : ") {
                        hf_new_finds = String::from(new_finds.trim());
                        hf_new_finds = String::from(
                            hf_new_finds
                                .strip_prefix("0 days ")
                                .unwrap_or(&hf_new_finds),
                        );
                        hf_new_finds = String::from(
                            hf_new_finds
                                .strip_prefix("00 hrs ")
                                .unwrap_or(&hf_new_finds),
                        );
                        hf_new_finds = String::from(
                            hf_new_finds
                                .strip_prefix("00 mins ")
                                .unwrap_or(&hf_new_finds),
                        );
                        hf_new_finds = String::from(
                            hf_new_finds.strip_suffix(" ago").unwrap_or(&hf_new_finds),
                        );
                    }
                }
            }
        }

        // Third step: Print stats
        // TODO Colors, of course!
        // Move 9 lines up and clear line
        eprint!("\x1B[9A\x1B[K");
        eprintln!("┌── afl++ {afl_status:0}───────────────────┬─ honggfuzz {hf_status:0}────────────────┐");
        eprint!("\x1B[K");
        eprintln!("│  total run time : {afl_total_run_time:17} │        run time : {hf_minimization_in:17} │");
        eprint!("\x1B[K");
        eprintln!(
            "│     total execs : {afl_total_execs:17} │     total execs : {hf_total_execs:17} │"
        );
        eprint!("\x1B[K");
        eprintln!("│       instances : {afl_instances:17} │         threads : {hf_threads:17} │");
        eprint!("\x1B[K");
        eprintln!("│cumulative speed : {afl_speed:17} │   average Speed : {hf_speed:17} │");
        eprint!("\x1B[K");
        eprintln!("│   best coverage : {afl_coverage:17} │        coverage : {hf_coverage:17} │");
        eprint!("\x1B[K");
        eprintln!("│   crashes saved : {afl_crashes:17} │   crashes saved : {hf_crashes:17} │");
        eprint!("\x1B[K");
        eprintln!("│ no new find for : {afl_new_finds:17} │ no new find for : {hf_new_finds:17} │");
        eprint!("\x1B[K");
        eprintln!("└─────────────────────────────────────┴─────────────────────────────────────┘");
    }
}

pub fn kill_subprocesses_recursively(pid: &str) -> Result<(), anyhow::Error> {
    let subprocesses = process::Command::new("pgrep")
        .arg(&format!("-P{pid}"))
        .output()?;

    for subprocess in std::str::from_utf8(&subprocesses.stdout)?.split('\n') {
        if subprocess.is_empty() {
            continue;
        }

        kill_subprocesses_recursively(subprocess)
            .context("Error in kill_subprocesses_recursively for pid {pid}")?;
    }

    info!("Killing pid {pid}");
    unsafe {
        libc::kill(pid.parse::<i32>().unwrap(), libc::SIGTERM);
    }
    Ok(())
}

// Stop all fuzzer processes
pub fn stop_fuzzers(processes: &mut Vec<process::Child>) -> Result<(), anyhow::Error> {
    info!("Stopping fuzzer processes");

    for process in processes {
        kill_subprocesses_recursively(&process.id().to_string())?;
        info!("Process kill: {:?}", process.kill());
        info!("Process wait: {:?}", process.wait());
    }
    Ok(())
}
