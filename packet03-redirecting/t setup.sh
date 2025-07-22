t setup -n uno --legacy-ip
t setup -n dos --legacy-ip
t setup -n tres --legacy-ip

t load -n uno -- --prog-name xdp_router_func xdp_prog_kern.o
t load -n dos -- --prog-name xdp_router_func xdp_prog_kern.o
t load -n tres -- --prog-name xdp_router_func xdp_prog_kern.o

t exec -n uno -- ./xdp-loader load --prog-name xdp_pass_func veth0 xdp_prog_kern.o
t exec -n dos -- ./xdp-loader load --prog-name xdp_pass_func veth0 xdp_prog_kern.o
t exec -n tres -- ./xdp-loader load --prog-name xdp_pass_func veth0 xdp_prog_kern.o

sudo ./xdp_stats -d uno
sudo ./xdp_stats -d dos
sudo ./xdp_stats -d tres