FROM golang:1.22 as build
WORKDIR /build
COPY . .
RUN make build

FROM registry.fedoraproject.org/fedora-minimal:latest
COPY --from=build /build/_output/veth-ethtool /usr/local/bin/veth-ethtool
RUN microdnf install -y iproute ethtool && microdnf clean all
