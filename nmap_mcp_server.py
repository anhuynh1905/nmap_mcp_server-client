from fastmcp import FastMCP
import subprocess
import os
import shortuuid
from typing import Optional, List, Dict, Any
from nmap_parser import NmapParser

# Create FastMCP server instance
app = FastMCP("nmap_mcp_server")

# Setup directory for nmap outputs
current_dir = os.getcwd()
output_dir = os.path.join(current_dir, "nmap_outputs")
os.makedirs(output_dir, exist_ok=True)

def generate_output_path(target: str, scan_type: str) -> str:
    """Generate a unique output path for scan results."""
    filename = f"{target}_{scan_type}_{shortuuid.uuid()[:8]}"
    return os.path.join(output_dir, f"{filename}.xml")

def run_nmap_scan(cmd: str, output_file: str) -> Dict[str, Any]:
    """Execute nmap command using Docker and return parsed results."""
    try:
        # Convert the output path to a Docker volume path
        docker_output_path = f"/out/{os.path.basename(output_file)}"
        
        # Build the Docker command
        docker_cmd = [
            "docker", "run", "--rm",
            "-v", f"{output_dir}:/out",
            "nmap",
            *cmd.split(),  # Split the nmap command into arguments
            "-oX", docker_output_path
        ]
        
        print(f"\n[DEBUG] Running Docker command: {' '.join(docker_cmd)}")
        
        # Run the Docker command
        result = subprocess.run(docker_cmd, capture_output=True, text=True)
        print(f"[DEBUG] Command return code: {result.returncode}")
        print(f"[DEBUG] Command stdout: {result.stdout[:200]}...")
        print(f"[DEBUG] Command stderr: {result.stderr}")
        
        # Check if command was successful
        if result.returncode == 0:
            # Check if output file exists
            print(f"[DEBUG] Checking if output file exists: {output_file}")
            if not os.path.exists(output_file):
                print(f"[DEBUG] Output file not found!")
                return {
                    "status": "error",
                    "message": f"Scan completed but output file {output_file} was not created"
                }
            
            try:
                print("[DEBUG] Attempting to parse XML file...")
                # Parse the XML output
                parser = NmapParser(output_file)
                parsed_data = parser.parse()
                print(f"[DEBUG] Successfully parsed {len(parsed_data)} hosts")
                
                summary = parser.get_summary()
                print(f"[DEBUG] Generated summary: {summary}")
                
                vulnerabilities = parser.get_vulnerabilities()
                print(f"[DEBUG] Found {len(vulnerabilities)} vulnerabilities")
                
                llm_summary = parser.get_llm_friendly_summary()
                print("[DEBUG] Generated LLM summary")
                
                return {
                    "status": "success",
                    "summary": summary,
                    "vulnerabilities": vulnerabilities,
                    "llm_summary": llm_summary,
                    "raw_data": parsed_data
                }
            except Exception as parse_error:
                print(f"[DEBUG] Error during parsing: {str(parse_error)}")
                return {
                    "status": "error",
                    "message": f"Error parsing scan results: {str(parse_error)}"
                }
        else:
            print(f"[DEBUG] Command failed with return code {result.returncode}")
            return {
                "status": "error",
                "message": f"Scan failed: {result.stderr}"
            }
    except Exception as e:
        print(f"[DEBUG] Unexpected error: {str(e)}")
        return {
            "status": "error",
            "message": f"Error during scan: {str(e)}"
        }

@app.tool(
    name="basic_scan",
    description="""Perform a basic network scan on a target host.
    This is a simple scan that identifies open ports and basic service information.
    Use this for quick reconnaissance of a target system.
    Returns structured data including port information, services, and summary statistics.
    """
)
def basic_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "basic")
    cmd = f"-sV {target}"  # Basic scan with version detection
    return run_nmap_scan(cmd, output_file)

@app.tool(
    name="aggressive_scan",
    description="""Perform an aggressive scan with OS detection, version detection, script scanning, and traceroute.
    This scan is more intrusive and provides detailed information about the target.
    Use this when you need comprehensive information about a target system.
    Returns detailed data including OS information, service versions, and vulnerability details.
    """
)
def aggressive_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "aggressive")
    cmd = f"-A -p- -sV --version-intensity 9 -O --script=all -T4 -v --reason --packet-trace {target}"
    return run_nmap_scan(cmd, output_file)

@app.tool(
    name="stealth_scan",
    description="""Perform a stealth scan using SYN scanning technique.
    This scan is less likely to be detected by intrusion detection systems.
    Use this when you need to scan without being detected.
    Returns port and service information while maintaining stealth.
    """
)
def stealth_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "stealth")
    cmd = f"-sS -sV -T2 {target}"
    return run_nmap_scan(cmd, output_file)

@app.tool(
    name="vulnerability_scan",
    description="""Perform a vulnerability scan using nmap's built-in scripts.
    This scan focuses on identifying potential security vulnerabilities.
    Use this when you need to assess the security posture of a target.
    Returns detailed vulnerability information and risk assessment.
    """
)
def vulnerability_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "vuln")
    cmd = f"-sV --script vuln {target}"
    return run_nmap_scan(cmd, output_file)

@app.tool(
    name="custom_scan",
    description="""Perform a custom scan with specified options.
    This allows for flexible scanning configurations based on specific needs.
    Use this when you need a tailored scanning approach.
    Returns structured data based on the custom scan configuration.
    """
)
def custom_scan(
    target: str,
    ports: Optional[str] = None,
    scripts: Optional[str] = None,
    timing: Optional[int] = None,
    verbose: bool = False
) -> Dict[str, Any]:
    output_file = generate_output_path(target, "custom")
    
    # Build command with optional parameters
    cmd_parts = []
    if ports:
        cmd_parts.append(f"-p{ports}")
    if scripts:
        cmd_parts.append(f"--script={scripts}")
    if timing:
        cmd_parts.append(f"-T{timing}")
    if verbose:
        cmd_parts.append("-v")
    
    cmd_parts.append(target)
    cmd = " ".join(cmd_parts)
    return run_nmap_scan(cmd, output_file)

@app.tool(
    name="service_scan",
    description="""Perform a detailed service version detection scan.
    This scan focuses on identifying running services and their versions.
    Use this when you need detailed information about running services.
    Returns comprehensive service information and version details.
    """
)
def service_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "service")
    cmd = f"-sV --version-intensity 9 {target}"
    return run_nmap_scan(cmd, output_file)

@app.tool(
    name="os_detection_scan",
    description="""Perform an operating system detection scan.
    This scan attempts to identify the target's operating system.
    Use this when you need to determine the OS of the target system.
    Returns detailed OS information and detection confidence levels.
    """
)
def os_detection_scan(target: str) -> Dict[str, Any]:
    output_file = generate_output_path(target, "os")
    cmd = f"-O --osscan-guess {target}"
    return run_nmap_scan(cmd, output_file)

if __name__ == "__main__":
    app.run(
        transport="streamable-http",
        host="127.0.0.1",
        port=4200,
        path="/nmap"
    ) 