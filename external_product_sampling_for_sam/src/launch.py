import subprocess

bashCommand = "RUSTFLAGS=\"-C target-cpu=native\" cargo run --release -- --tot {} --id {}"
tot = 7

for id in range(tot):
    cmd = bashCommand.format(tot, id)
    print(cmd)
    process = subprocess.Popen(cmd, shell=True)

