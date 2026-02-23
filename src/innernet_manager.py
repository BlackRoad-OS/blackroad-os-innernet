"""Private WireGuard-based mesh network manager (innernet-inspired)."""
import sqlite3
import uuid
import json
import base64
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import argparse
import ipaddress


DB_PATH = Path.home() / ".blackroad" / "innernet.db"


@dataclass
class Peer:
    """Network peer definition."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    ip: str = ""
    public_key: str = ""
    allowed_ips: str = ""
    endpoint: Optional[str] = None
    last_handshake: Optional[datetime] = None
    status: str = "disconnected"  # connected, disconnected
    groups: List[str] = field(default_factory=list)


@dataclass
class Network:
    """Private mesh network definition."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    cidr: str = ""
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    peer_count: int = 0


class InnernetManager:
    """Private WireGuard-based mesh network manager."""
    
    # Pre-configured BlackRoad Pi network
    PREDEFINED_NETWORK = "BlackRoad-Pi"
    PREDEFINED_PEERS = ["aria64", "alice", "blackroad-pi", "macbook"]
    
    def __init__(self):
        self._init_db()
        self._populate_defaults()
    
    def _init_db(self):
        """Initialize SQLite database."""
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS networks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    cidr TEXT NOT NULL,
                    description TEXT,
                    created_at TEXT,
                    peer_count INTEGER
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS peers (
                    id TEXT PRIMARY KEY,
                    network_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    ip TEXT,
                    public_key TEXT,
                    allowed_ips TEXT,
                    endpoint TEXT,
                    last_handshake TEXT,
                    status TEXT,
                    groups TEXT,
                    FOREIGN KEY (network_id) REFERENCES networks(id),
                    UNIQUE(network_id, name)
                )
            """)
            conn.commit()
    
    def _populate_defaults(self):
        """Populate pre-configured network and peers."""
        # Check if network already exists
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute("""
                SELECT id FROM networks WHERE name = ?
            """, (self.PREDEFINED_NETWORK,))
            if cursor.fetchone():
                return
        
        # Create network
        network_id = self.create_network(
            self.PREDEFINED_NETWORK,
            "10.0.0.0/8",
            "BlackRoad Pi mesh network"
        )
        
        # Add peers
        for i, peer_name in enumerate(self.PREDEFINED_PEERS):
            ip = f"10.0.0.{i + 2}"
            self.add_peer(network_id, peer_name, ip)
    
    def create_network(self, name: str, cidr: str = "10.0.0.0/8", 
                      description: str = "") -> str:
        """Create a new private network."""
        # Validate CIDR
        try:
            ipaddress.ip_network(cidr)
        except ValueError:
            raise ValueError(f"Invalid CIDR: {cidr}")
        
        network_id = str(uuid.uuid4())
        network = Network(id=network_id, name=name, cidr=cidr, description=description)
        
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO networks (id, name, cidr, description, created_at, peer_count)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (network.id, network.name, network.cidr, network.description,
                  network.created_at.isoformat(), 0))
            conn.commit()
        
        return network_id
    
    def add_peer(self, network_id: str, name: str, ip: str = None) -> str:
        """Add a peer to the network."""
        # Get network info
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute("SELECT cidr FROM networks WHERE id = ?", (network_id,))
            result = cursor.fetchone()
            if not result:
                raise ValueError(f"Network {network_id} not found")
            cidr = result[0]
        
        # Auto-assign IP if not provided
        if ip is None:
            network = ipaddress.ip_network(cidr)
            existing_ips = set()
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.execute("SELECT ip FROM peers WHERE network_id = ?", (network_id,))
                existing_ips = {row[0] for row in cursor.fetchall() if row[0]}
            
            for candidate in network.hosts():
                candidate_str = str(candidate)
                if candidate_str not in existing_ips:
                    ip = candidate_str
                    break
        
        # Generate mock WireGuard keypair
        public_key = base64.b64encode(os.urandom(32)).decode()
        private_key = base64.b64encode(os.urandom(32)).decode()
        
        peer_id = str(uuid.uuid4())
        peer = Peer(
            id=peer_id,
            name=name,
            ip=ip,
            public_key=public_key,
            allowed_ips=f"{ip}/32",
            status="disconnected"
        )
        
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO peers (id, network_id, name, ip, public_key, allowed_ips, 
                                  endpoint, last_handshake, status, groups)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (peer.id, network_id, peer.name, peer.ip, peer.public_key,
                  peer.allowed_ips, None, None, peer.status, json.dumps([])))
            
            # Update peer count
            conn.execute("""
                UPDATE networks SET peer_count = peer_count + 1 WHERE id = ?
            """, (network_id,))
            conn.commit()
        
        return peer_id
    
    def remove_peer(self, network_id: str, peer_name: str) -> None:
        """Remove a peer from the network."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                DELETE FROM peers WHERE network_id = ? AND name = ?
            """, (network_id, peer_name))
            
            conn.execute("""
                UPDATE networks SET peer_count = peer_count - 1 
                WHERE id = ? AND peer_count > 0
            """, (network_id,))
            conn.commit()
    
    def generate_config(self, peer_name: str) -> str:
        """Generate wg-quick config string for a peer."""
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute("""
                SELECT peers.ip, peers.public_key, networks.cidr, peers.id
                FROM peers
                JOIN networks ON peers.network_id = networks.id
                WHERE peers.name = ?
            """, (peer_name,))
            result = cursor.fetchone()
            if not result:
                raise ValueError(f"Peer {peer_name} not found")
            
            ip, public_key, cidr, peer_id = result
        
        # Generate mock private key
        private_key = base64.b64encode(os.urandom(32)).decode()
        
        config = f"""[Interface]
Address = {ip}/24
PrivateKey = {private_key}
ListenPort = 51820
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = {public_key}
AllowedIPs = {cidr}
Endpoint = 10.0.0.1:51820
PersistentKeepalive = 25
"""
        return config
    
    def get_status(self) -> Dict[str, any]:
        """Get status of all networks and connected peers."""
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            
            # Get networks
            cursor = conn.execute("SELECT * FROM networks")
            networks = [dict(row) for row in cursor.fetchall()]
            
            # Get connected peers
            cursor = conn.execute("""
                SELECT COUNT(*) as connected_count FROM peers WHERE status = 'connected'
            """)
            connected = cursor.fetchone()['connected_count']
        
        return {
            'networks': networks,
            'connected_peers': connected,
            'total_peers': sum(n['peer_count'] for n in networks),
            'timestamp': datetime.now().isoformat()
        }
    
    def ping_peer(self, peer_name: str) -> Dict[str, any]:
        """Simulate connectivity check for a peer."""
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute("""
                SELECT id, ip, status FROM peers WHERE name = ?
            """, (peer_name,))
            result = cursor.fetchone()
            if not result:
                raise ValueError(f"Peer {peer_name} not found")
            
            peer_id, ip, status = result
        
        # Simulate ping result (deterministic based on peer name hash)
        is_reachable = hash(peer_name) % 3 != 0  # ~67% reachable
        
        if is_reachable:
            # Update status to connected
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute("""
                    UPDATE peers SET status = 'connected', last_handshake = ?
                    WHERE id = ?
                """, (datetime.now().isoformat(), peer_id))
                conn.commit()
        
        return {
            'peer': peer_name,
            'ip': ip,
            'reachable': is_reachable,
            'latency_ms': (hash(peer_name) % 100) + 5 if is_reachable else None,
            'timestamp': datetime.now().isoformat()
        }
    
    def list_peers(self, network_id: str = None, group: str = None) -> List[Dict]:
        """List peers with optional filtering."""
        query = "SELECT * FROM peers"
        params = []
        
        if network_id:
            query += " WHERE network_id = ?"
            params.append(network_id)
        
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(query, params)
            peers = [dict(row) for row in cursor.fetchall()]
        
        # Filter by group if specified
        if group:
            filtered = []
            for peer in peers:
                groups = json.loads(peer['groups']) if peer['groups'] else []
                if group in groups:
                    filtered.append(peer)
            return filtered
        
        return peers
    
    def assign_group(self, peer_name: str, group: str) -> None:
        """Assign a peer to a group."""
        if group not in ["admin", "workers", "sensors", "public", "internal"]:
            raise ValueError(f"Invalid group: {group}")
        
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute("""
                SELECT groups FROM peers WHERE name = ?
            """, (peer_name,))
            result = cursor.fetchone()
            if not result:
                raise ValueError(f"Peer {peer_name} not found")
            
            groups = json.loads(result[0]) if result[0] else []
            if group not in groups:
                groups.append(group)
            
            conn.execute("""
                UPDATE peers SET groups = ? WHERE name = ?
            """, (json.dumps(groups), peer_name))
            conn.commit()
    
    def export_network_map(self, network_id: str) -> str:
        """ASCII map of peer connections."""
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute("""
                SELECT name, ip, status FROM peers WHERE network_id = ?
                ORDER BY name
            """, (network_id,))
            peers = cursor.fetchall()
            
            cursor = conn.execute("""
                SELECT name FROM networks WHERE id = ?
            """, (network_id,))
            network = cursor.fetchone()
        
        lines = [
            "╔════════════════════════════════════════╗",
            f"║ Network: {network[0] if network else 'Unknown':<31} ║",
            "╠════════════════════════════════════════╣",
        ]
        
        for name, ip, status in peers:
            status_icon = "● " if status == "connected" else "○ "
            line = f"║ {status_icon}{name:<16} {ip:<18} │"
            lines.append(line)
        
        lines.append("╚════════════════════════════════════════╝")
        
        return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Innernet Manager")
    subparsers = parser.add_subparsers(dest="command")
    
    # Status command
    status_parser = subparsers.add_parser("status")
    
    # Config command
    config_parser = subparsers.add_parser("config")
    config_parser.add_argument("peer_name", help="Peer name")
    
    # Map command
    map_parser = subparsers.add_parser("map")
    map_parser.add_argument("network_id", help="Network ID")
    
    args = parser.parse_args()
    manager = InnernetManager()
    
    if args.command == "status":
        status = manager.get_status()
        print(json.dumps(status, indent=2))
    elif args.command == "config":
        config = manager.generate_config(args.peer_name)
        print(config)
    elif args.command == "map":
        map_str = manager.export_network_map(args.network_id)
        print(map_str)


if __name__ == "__main__":
    main()
