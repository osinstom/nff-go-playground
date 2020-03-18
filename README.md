To run this app:

```bash
NFF_GO=<PATH-TO-NFF-GP> source env.sh
go build main.go
docker build -t dev/nff-go-playground .
docker run -it --privileged -v /sys/bus/pci/drivers:/sys/bus/pci/drivers -v /sys/kernel/mm/hugepages:/sys/kernel/mm/hugepages -v /sys/devices/system/node:/sys/devices/system/node -v /dev:/dev dev/nff-go-playground:latest
```