
import subprocess

bashCommand = "RUSTFLAGS=\"-Ctarget-cpu=native\" cargo run --release -- --poly-size {}"
scp_bashcomand = "scp -i gpu_tests.pem ubuntu@ec2-35-180-134-133.eu-west-3.compute.amazonaws.com:/home/ubuntu/concrete/external_product_sampling_for_sam/src/2048.acquisition_external_product_k=1 2048.acquisition_external_product_k=1"
# bashCommand = "cargo run --release -- --poly-size {}"

N_MIN = 8
N_MAX = 10 #14 + 1
poly_sizes= [2**N for N in range(N_MIN, N_MAX)]
for N in poly_sizes:
    cmd = bashCommand.format(N)
    print(cmd)
    process = subprocess.Popen(cmd, shell=True)



