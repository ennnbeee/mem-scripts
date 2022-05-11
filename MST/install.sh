# Signing in user is Intune licensed

sudo apt-get update

sudo apt-get install ca-certificates curl gnupg lsb-release jq

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-compose-plugin

sudo docker run hello-world

wget --output-document=mst-readiness https://aka.ms/microsofttunnelready
sudo chmod +x ./mst-readiness
sudo ./mst-readiness network
./mst-readiness account

wget --output-document=mstunnel-setup https://aka.ms/microsofttunneldownload
sudo chmod +x ./mstunnel-setup
sudo ./mstunnel-setup



/etc/mstunnel/private/site.pfx