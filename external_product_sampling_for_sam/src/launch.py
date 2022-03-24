
import subprocess

bashCommand = "RUSTFLAGS=\"-Ctarget-cpu=native\" cargo run --release -- --tot {} --id {}"
scp_bashcomand = "scp -i gpu_tests.pem ubuntu@ec2-35-180-134-133.eu-west-3.compute.amazonaws.com:/home/ubuntu/concrete/external_product_sampling_for_sam/src/2048.acquisition_external_product_k=1 2048.acquisition_external_product_k=1"
# bashCommand = "cargo run --release -- --poly-size {}"

tot=10

for id in range(tot):
    cmd = bashCommand.format(tot, id)
    print(cmd)
    process = subprocess.Popen(cmd, shell=True)



