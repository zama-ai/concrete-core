
import subprocess

bashCommand = "RUSTFLAGS=\"-Ctarget-cpu=native\" cargo run --release -- --poly-size {}"
# bashCommand = "cargo run --release -- --poly-size {}"

N_MIN = 8
N_MAX = 10 #14 + 1
poly_sizes= [2**N for N in range(N_MIN, N_MAX)]
for N in poly_sizes:
    cmd = bashCommand.format(N)
    print(cmd)
    process = subprocess.Popen(cmd, shell=True)
