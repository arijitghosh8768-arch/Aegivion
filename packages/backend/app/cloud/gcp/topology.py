from typing import List, Dict, Any

def generate_gcp_topology(assets: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Transforms GCP assets into a standard node/edge schema for the Topology graph UI.
    """
    nodes = []
    edges = []
    
    # 1. Add nodes
    for asset in assets:
        if asset.get("provider") == "gcp":
            node_id = asset.get("asset_id")
            asset_type = asset.get("type")
            
            node_data = {
                "id": node_id,
                "label": asset.get("name", node_id),
                "type": "gcp_compute" if asset_type == "COMPUTE_INSTANCE" else "gcp_iam" if asset_type == "IDENTITY" else "gcp_resource",
                "status": "warning" if asset_type == "COMPUTE_INSTANCE" and asset.get("configuration", {}).get("public_ip") else "ok"
            }
            nodes.append(node_data)
            
            # 2. Add edges (e.g. Service Account attached to Compute Instance)
            if asset_type == "COMPUTE_INSTANCE":
                sa = asset.get("configuration", {}).get("service_account")
                if sa:
                    # Find the corresponding identity node
                    for other in assets:
                        if other.get("type") == "IDENTITY" and other.get("configuration", {}).get("email") == sa:
                            edges.append({
                                "id": f"edge-{node_id}-{other.get('asset_id')}",
                                "source": node_id,
                                "target": other.get("asset_id"),
                                "label": "uses service account"
                            })
                            
    return {
        "nodes": nodes,
        "edges": edges
    }
