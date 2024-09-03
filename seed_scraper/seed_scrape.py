import subprocess
import time

image_location = "/home/ubuntu/FYP/images/rehosted_img_aug/85_813c23b285d234785f1c4ce19c76bf76d148e06977b6f016f6590e59d6d17f65.tar.gz"
subprocess.Popen(['bash', 'docker_compose.sh',image_location])
time.sleep(20)
print("after sleep")


