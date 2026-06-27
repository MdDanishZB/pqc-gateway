import subprocess
import argparse
import sys

class NetworkConditioner:
    """
    Wraps 'tc netem' to simulate network impairments like latency, loss, and jitter.
    Requires sudo privileges for 'tc' commands.
    """
    def __init__(self, interface="lo"):
        self.interface = interface

    def apply_conditions(self, loss=0, delay=0, jitter=0):
        """
        Applies network conditions using tc netem.
        :param loss: Percentage of packet loss (0-100)
        :param delay: Latency in milliseconds
        :param jitter: Jitter in milliseconds
        """
        # Always clear existing rules first
        self.reset()
        
        if loss == 0 and delay == 0 and jitter == 0:
            print(f"[*] Network conditions reset on {self.interface}")
            return True

        # Build the tc command
        # sudo tc qdisc add dev lo root netem loss 5% delay 50ms 10ms distribution normal
        cmd = [
            "sudo", "tc", "qdisc", "add", "dev", self.interface, "root", "netem"
        ]
        
        if loss > 0:
            cmd.extend(["loss", f"{loss}%"])
        
        if delay > 0:
            cmd.extend(["delay", f"{delay}ms"])
            if jitter > 0:
                cmd.extend([f"{jitter}ms", "distribution", "normal"])
        
        print(f"[*] Applying: loss={loss}%, delay={delay}ms, jitter={jitter}ms on {self.interface}")
        
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"[!] Error applying conditions: {e.stderr.strip()}")
            return False

    def reset(self):
        """Removes all netem rules from the interface."""
        cmd = ["sudo", "tc", "qdisc", "del", "dev", self.interface, "root"]
        try:
            # We don't check=True here because it fails if no rules exist
            subprocess.run(cmd, capture_output=True, text=True)
            return True
        except Exception as e:
            print(f"[!] Error resetting conditions: {e}")
            return False

    def get_status(self):
        """Returns the current tc qdisc configuration for the interface."""
        try:
            result = subprocess.run(["tc", "qdisc", "show", "dev", self.interface], 
                                    capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except Exception as e:
            return f"Error: {e}"

    def block_path(self, ip="127.0.0.1", port=5000):
        """Blocks a specific IP/port using iptables DROP rules."""
        try:
            subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-p", "sctp", "--dport", str(port), "-j", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-I", "OUTPUT", "1", "-d", ip, "-p", "sctp", "--dport", str(port), "-j", "DROP"], check=True)
            print(f"[*] Path BLOCKED: {ip}:{port}")
            return True
        except Exception as e:
            print(f"[!] Error blocking path: {e}")
            return False

    def unblock_path(self, ip="127.0.0.1", port=5000):
        """Removes iptables DROP rules for a specific IP/port."""
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-p", "sctp", "--dport", str(port), "-j", "DROP"], capture_output=True)
            subprocess.run(["sudo", "iptables", "-D", "OUTPUT", "-d", ip, "-p", "sctp", "--dport", str(port), "-j", "DROP"], capture_output=True)
            print(f"[*] Path RESTORED: {ip}:{port}")
            return True
        except Exception as e:
            print(f"[!] Error unblocking path: {e}")
            return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PQC Gateway Network Conditioner")
    parser.add_argument("--interface", type=str, default="lo", help="Interface to impair")
    parser.add_argument("--loss", type=float, default=0, help="Packet loss percentage (0-100)")
    parser.add_argument("--delay", type=int, default=0, help="Latency in ms")
    parser.add_argument("--jitter", type=int, default=0, help="Jitter in ms")
    parser.add_argument("--reset", action="store_true", help="Reset all conditions")
    parser.add_argument("--status", action="store_true", help="Show current status")

    args = parser.parse_args()
    conditioner = NetworkConditioner(args.interface)

    if args.reset:
        conditioner.reset()
        print(f"[*] Conditions reset on {args.interface}")
    elif args.status:
        print(f"[*] Current status for {args.interface}:")
        print(conditioner.get_status())
    else:
        conditioner.apply_conditions(args.loss, args.delay, args.jitter)
