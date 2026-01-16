include .env
export

.PHONY: build build-controlplane build-gateway build-agent build-protected1 build-protected2 \
        deploy-controlplane deploy-gateway deploy-protected1 deploy-protected2 \
        stop-controlplane stop-gateway stop-protected1 stop-protected2 \
        logs-controlplane logs-gateway logs-protected1 logs-protected2 \
        ssh-controlplane ssh-gateway ssh-protected1 ssh-protected2

# Build
build: build-controlplane build-gateway build-agent build-protected1 build-protected2

build-controlplane:
	GOOS=linux GOARCH=amd64 go build -o controlplane/controlplane ./controlplane/cmd/controlplane

build-gateway:
	GOOS=linux GOARCH=amd64 go build -o gateway/gateway ./gateway/cmd/gateway

build-agent:
	go build -o agent/agent ./agent/cmd/agent

build-protected1:
	GOOS=linux GOARCH=amd64 go build -o protected-resource1/protected-resource1 ./protected-resource1

build-protected2:
	GOOS=linux GOARCH=amd64 go build -o protected-resource2/protected-resource2 ./protected-resource2

# Deploy
deploy-controlplane: build-controlplane
	gcloud compute scp controlplane/controlplane $(INSTANCE_CONTROLPLANE):~ --zone=$(ZONE_CONTROLPLANE) --tunnel-through-iap
	@echo 'pkill -f "./controlplane" || true; nohup env CONTROLPLANE_BASIC_USER=$(CONTROLPLANE_BASIC_USER) CONTROLPLANE_BASIC_PASS=$(CONTROLPLANE_BASIC_PASS) JWT_SECRET=$(JWT_SECRET) ./controlplane > controlplane.log 2>&1 & sleep 1 && pgrep -f "./controlplane" && echo Started' > /tmp/start-controlplane.sh
	gcloud compute scp /tmp/start-controlplane.sh $(INSTANCE_CONTROLPLANE):~ --zone=$(ZONE_CONTROLPLANE) --tunnel-through-iap
	gcloud compute ssh $(INSTANCE_CONTROLPLANE) --zone=$(ZONE_CONTROLPLANE) --tunnel-through-iap -- bash ~/start-controlplane.sh

deploy-gateway: build-gateway
	gcloud compute scp gateway/gateway $(INSTANCE_GATEWAY):~ --zone=$(ZONE_GATEWAY) --tunnel-through-iap
	@echo 'sudo pkill -f "./gateway" || true; sudo sysctl -w net.ipv4.ip_forward=1; sudo nohup env CONTROLPLANE_URL=$(CONTROLPLANE_URL) API_KEY=$(API_KEY) ./gateway > gateway.log 2>&1 & sleep 1 && pgrep -f "./gateway" && echo Started' > /tmp/start-gateway.sh
	gcloud compute scp /tmp/start-gateway.sh $(INSTANCE_GATEWAY):~ --zone=$(ZONE_GATEWAY) --tunnel-through-iap
	gcloud compute ssh $(INSTANCE_GATEWAY) --zone=$(ZONE_GATEWAY) --tunnel-through-iap -- bash ~/start-gateway.sh

deploy-protected1: build-protected1
	gcloud compute scp protected-resource1/protected-resource1 $(INSTANCE_PROTECTED1):~ --zone=$(ZONE_PROTECTED1) --tunnel-through-iap
	@echo 'pkill -f "./protected-resource1" || true; nohup ./protected-resource1 > protected-resource1.log 2>&1 & sleep 1 && pgrep -f "./protected-resource1" && echo Started' > /tmp/start-protected1.sh
	gcloud compute scp /tmp/start-protected1.sh $(INSTANCE_PROTECTED1):~ --zone=$(ZONE_PROTECTED1) --tunnel-through-iap
	gcloud compute ssh $(INSTANCE_PROTECTED1) --zone=$(ZONE_PROTECTED1) --tunnel-through-iap -- bash ~/start-protected1.sh

deploy-protected2: build-protected2
	gcloud compute scp protected-resource2/protected-resource2 $(INSTANCE_PROTECTED2):~ --zone=$(ZONE_PROTECTED2) --tunnel-through-iap
	@echo 'pkill -f "./protected-resource2" || true; nohup ./protected-resource2 > protected-resource2.log 2>&1 & sleep 1 && pgrep -f "./protected-resource2" && echo Started' > /tmp/start-protected2.sh
	gcloud compute scp /tmp/start-protected2.sh $(INSTANCE_PROTECTED2):~ --zone=$(ZONE_PROTECTED2) --tunnel-through-iap
	gcloud compute ssh $(INSTANCE_PROTECTED2) --zone=$(ZONE_PROTECTED2) --tunnel-through-iap -- bash ~/start-protected2.sh

# Stop
stop-controlplane:
	gcloud compute ssh $(INSTANCE_CONTROLPLANE) --zone=$(ZONE_CONTROLPLANE) --tunnel-through-iap -- pkill -f "./controlplane" && echo Stopped || echo "Not running"

stop-gateway:
	gcloud compute ssh $(INSTANCE_GATEWAY) --zone=$(ZONE_GATEWAY) --tunnel-through-iap -- sudo pkill -f "./gateway" && echo Stopped || echo "Not running"

stop-protected1:
	gcloud compute ssh $(INSTANCE_PROTECTED1) --zone=$(ZONE_PROTECTED1) --tunnel-through-iap -- pkill -f "./protected-resource1" && echo Stopped || echo "Not running"

stop-protected2:
	gcloud compute ssh $(INSTANCE_PROTECTED2) --zone=$(ZONE_PROTECTED2) --tunnel-through-iap -- pkill -f "./protected-resource2" && echo Stopped || echo "Not running"

# Logs (usage: make logs-controlplane LINES=100)
LINES ?= 50

logs-controlplane:
	gcloud compute ssh $(INSTANCE_CONTROLPLANE) --zone=$(ZONE_CONTROLPLANE) --tunnel-through-iap -- tail -n $(LINES) -f controlplane.log

logs-gateway:
	gcloud compute ssh $(INSTANCE_GATEWAY) --zone=$(ZONE_GATEWAY) --tunnel-through-iap -- sudo tail -n $(LINES) -f gateway.log

logs-protected1:
	gcloud compute ssh $(INSTANCE_PROTECTED1) --zone=$(ZONE_PROTECTED1) --tunnel-through-iap -- tail -n $(LINES) -f protected-resource1.log

logs-protected2:
	gcloud compute ssh $(INSTANCE_PROTECTED2) --zone=$(ZONE_PROTECTED2) --tunnel-through-iap -- tail -n $(LINES) -f protected-resource2.log

# SSH
ssh-controlplane:
	gcloud compute ssh $(INSTANCE_CONTROLPLANE) --zone=$(ZONE_CONTROLPLANE) --tunnel-through-iap

ssh-gateway:
	gcloud compute ssh $(INSTANCE_GATEWAY) --zone=$(ZONE_GATEWAY) --tunnel-through-iap

ssh-protected1:
	gcloud compute ssh $(INSTANCE_PROTECTED1) --zone=$(ZONE_PROTECTED1) --tunnel-through-iap

ssh-protected2:
	gcloud compute ssh $(INSTANCE_PROTECTED2) --zone=$(ZONE_PROTECTED2) --tunnel-through-iap
