from flask import Flask, render_template, request, jsonify, redirect, url_for
from fastmcp import Client
import asyncio
import os
from dotenv import load_dotenv
import json
import logging
import markdown
from markdown.extensions import fenced_code, tables, nl2br

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('nmap_web_app')

app = Flask(__name__)

# Initialize MCP client
logger.debug("Initializing MCP client...")
mcp_client = Client("http://127.0.0.1:4200/nmap")

async def get_mcp_client():
    """Get a new MCP client instance for each request"""
    return Client("http://127.0.0.1:4200/nmap")

def process_markdown(text):
    """Convert markdown text to HTML with extensions"""
    extensions = [
        'fenced_code',  # For code blocks
        'tables',       # For markdown tables
        'nl2br',        # Convert newlines to <br>
        'extra'         # Additional markdown features
    ]
    return markdown.markdown(text, extensions=extensions)

def process_mcp_response(response):
    """Process FastMCP response to make it JSON serializable."""
    print(f"[DEBUG] Processing MCP response type: {type(response)}")
    print(f"[DEBUG] Raw response: {response}")
    
    # Handle FastMCP 2.3.4 response format (list of TextContent)
    if isinstance(response, list) and len(response) > 0:
        # Extract text content from the first item
        text_content = response[0].text
        print(f"[DEBUG] Extracted text content: {text_content}")
        try:
            # Parse the JSON string
            parsed = json.loads(text_content)
            print(f"[DEBUG] Successfully parsed JSON: {parsed}")
            return parsed
        except json.JSONDecodeError as e:
            print(f"[DEBUG] Failed to parse JSON: {e}")
            return text_content
    
    # Handle other response types
    if isinstance(response, str):
        try:
            parsed = json.loads(response)
            print(f"[DEBUG] Successfully parsed string as JSON: {parsed}")
            return parsed
        except json.JSONDecodeError as e:
            print(f"[DEBUG] Failed to parse string as JSON: {e}")
            return response
    
    if isinstance(response, (dict, list)):
        print(f"[DEBUG] Returning dict/list directly: {response}")
        return response
    
    try:
        str_response = str(response)
        print(f"[DEBUG] Converted to string: {str_response}")
        return str_response
    except Exception as e:
        print(f"[DEBUG] Failed to convert response to string: {e}")
        return {"error": "Could not serialize response"}

@app.route('/')
def index():
    logger.debug("Rendering index page")
    return render_template('index.html')

@app.route('/history')
def history():
    try:
        logger.debug("Getting scan history")
        async def get_history():
            async with mcp_client:
                logger.debug("Calling get_scan_history tool")
                result = await mcp_client.call_tool("get_scan_history")
                logger.debug(f"History result: {result}")
                return result
        scans = asyncio.run(get_history())
        logger.debug(f"Retrieved {len(scans)} scan records")
        return render_template('history.html', scans=process_mcp_response(scans))
    except Exception as e:
        logger.error(f"Error in scan_history: {str(e)}", exc_info=True)
        return render_template('history.html', scans=[], error=str(e))

@app.route('/stats')
def stats():
    """Render the statistics page"""
    return render_template('stats.html')

@app.route('/stats/overview')
def stats_overview():
    """Get statistics overview data"""
    try:
        async def get_stats():
            async with mcp_client:
                result = await mcp_client.read_resource("resource://stats/overview")
                return result
        stats = asyncio.run(get_stats())
        return jsonify(process_mcp_response(stats))
    except Exception as e:
        logger.error(f"Error getting scan stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/scan', methods=['POST'])
def start_scan():
    try:
        target = request.form.get('target')
        scan_type = request.form.get('scan_type')
        logger.debug(f"Starting scan - Target: {target}, Type: {scan_type}")
        
        if not target or not scan_type:
            return jsonify({'error': 'Missing target or scan type'})

        scan_type_map = {
            'basic': 'basic_scan',
            'aggressive': 'aggressive_scan',
            'stealth': 'stealth_scan',
            'vuln': 'vulnerability_scan',
            'service': 'service_scan',
            'os': 'os_detection_scan'
        }
        tool_name = scan_type_map.get(scan_type)
        if not tool_name:
            return jsonify({'error': 'Invalid scan type'})

        async def run_scan():
            logger.debug(f"Calling {tool_name} tool")
            async with mcp_client:
                result = await mcp_client.call_tool(tool_name, {"target": target})
                logger.debug(f"Scan result: {result}")
                return result
        
        result = asyncio.run(run_scan())
        logger.debug(f"Scan completed with status: {result.get('status', 'unknown')}")
        
        if result.get('status') == 'success':
            return redirect(url_for('scan_details', target=target, scan_type=scan_type))
        else:
            logger.error(f"Scan failed: {result.get('message', 'Unknown error')}")
            return render_template('error.html', error=result.get('message', 'Scan failed'))
    except Exception as e:
        logger.error(f"Error in start_scan: {str(e)}", exc_info=True)
        return render_template('error.html', error=str(e))

@app.route('/scan/<target>/<scan_type>')
def scan_details(target, scan_type):
    try:
        logger.debug(f"Getting scan details - Target: {target}, Type: {scan_type}")
        async def get_details():
            client = await get_mcp_client()
            async with client:
                # First get the scan history to find the most recent scan time
                logger.debug("Getting scan history to find latest scan time")
                history = await client.call_tool("get_scan_history", {})
                logger.debug(f"History result: {history}")
                
                # Process the history response
                if isinstance(history, list) and len(history) > 0:
                    # Extract text content from the first item if it's a TextContent object
                    history_data = history[0].text if hasattr(history[0], 'text') else history
                    try:
                        history_data = json.loads(history_data) if isinstance(history_data, str) else history_data
                    except json.JSONDecodeError:
                        logger.error(f"Failed to parse history data as JSON: {history_data}")
                        return {'error': 'Invalid history data format'}
                else:
                    logger.error("No history data received")
                    return {'error': 'No scan history available'}
                
                # Find the most recent scan for this target and type
                latest_scan = None
                for scan in history_data:
                    if isinstance(scan, dict) and scan.get('target') == target and scan.get('scan_type') == scan_type:
                        latest_scan = scan
                        break
                
                if not latest_scan:
                    return {'error': 'No scan found for this target and type'}
                
                # Now get the detailed information using the scan time
                logger.debug(f"Calling get_scan_details tool with scan_time: {latest_scan['scan_time']}")
                result = await client.call_tool("get_scan_details", {
                    "target": target,
                    "scan_type": scan_type,
                    "scan_time": latest_scan['scan_time']
                })
                logger.debug(f"Scan details result: {result}")
                
                # Process the scan details response
                if isinstance(result, list) and len(result) > 0:
                    result_data = result[0].text if hasattr(result[0], 'text') else result
                    try:
                        result_data = json.loads(result_data) if isinstance(result_data, str) else result_data
                        return result_data
                    except json.JSONDecodeError:
                        logger.error(f"Failed to parse scan details as JSON: {result_data}")
                        return {'error': 'Invalid scan details format'}
                else:
                    logger.error("No scan details received")
                    return {'error': 'No scan details available'}
        
        result = asyncio.run(get_details())
        logger.debug(f"Retrieved scan details with status: {result.get('status', 'unknown')}")
        
        if 'error' in result:
            logger.error(f"Error getting scan details: {result['error']}")
            return render_template('error.html', error=result['error'])
        
        # Extract the parsed data and ensure we have the required fields
        parsed_data = result.get('parsed_data', {})
        if not parsed_data:
            logger.error("No parsed data in scan details")
            return render_template('error.html', error='No scan data available')
            
        # Extract summary and other data
        summary = parsed_data.get('summary', {})
        vulnerabilities = parsed_data.get('vulnerabilities', [])
        llm_summary = parsed_data.get('llm_summary', '')
        raw_data = parsed_data.get('raw_data', [])
            
        return render_template('scan_details.html', 
                             target=target,
                             scan_type=scan_type,
                             summary=summary,
                             vulnerabilities=vulnerabilities,
                             llm_summary=llm_summary,
                             raw_data=raw_data)
                             
    except Exception as e:
        logger.error(f"Error in scan_details: {str(e)}", exc_info=True)
        return render_template('error.html', error=str(e))

# New endpoints for retrieving and deleting by scan ID

@app.route('/scan/retrieve/<int:scan_id>', methods=['GET'])
def retrieve_scan(scan_id):
    """Retrieve a past scan (JSON) by its database ID."""
    try:
        async def get_scan():
            async with mcp_client:
                return await mcp_client.call_tool("retrieve_scan", {"scan_id": scan_id})
        result = asyncio.run(get_scan())
        return jsonify(process_mcp_response(result))
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/scan/delete/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a past scan record and its XML file by database ID."""
    try:
        async def del_scan():
            async with mcp_client:
                return await mcp_client.call_tool("delete_scan", {"scan_id": scan_id})
        result = asyncio.run(del_scan())
        return jsonify(process_mcp_response(result))
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/scan/<target>/<scan_type>/analyze')
def analyze_scan(target, scan_type):
    try:
        logger.debug(f"Starting scan analysis - Target: {target}, Type: {scan_type}")
        async def get_analysis():
            client = await get_mcp_client()
            async with client:
                logger.debug("Calling analyze_scan tool")
                result = await client.call_tool("analyze_scan", {
                    "target": target,
                    "scan_type": scan_type
                })
                logger.debug(f"Analysis result: {result}")
                
                # Process the analysis response
                if isinstance(result, list) and len(result) > 0:
                    result_data = result[0].text if hasattr(result[0], 'text') else result
                    try:
                        result_data = json.loads(result_data) if isinstance(result_data, str) else result_data
                        return result_data
                    except json.JSONDecodeError:
                        logger.error(f"Failed to parse analysis as JSON: {result_data}")
                        return {'error': 'Invalid analysis format'}
                else:
                    logger.error("No analysis data received")
                    return {'error': 'No analysis available'}
        
        result = asyncio.run(get_analysis())
        logger.debug(f"Analysis completed with status: {result.get('status', 'unknown')}")
        
        if 'error' in result:
            logger.error(f"Error in analysis: {result['error']}")
            return render_template('error.html', error=result['error'])
            
        # Extract the analysis data
        analysis = result.get('ai_analysis', {})
        if not analysis:
            logger.error("No analysis data in result")
            return render_template('error.html', error='No analysis data available')
        
        # Process markdown content if present
        if isinstance(analysis, dict) and 'analysis' in analysis:
            analysis['analysis'] = process_markdown(analysis['analysis'])
            
        return render_template('analysis.html',
                             target=target,
                             scan_type=scan_type,
                             analysis=analysis)
                             
    except Exception as e:
        logger.error(f"Error in analyze_scan: {str(e)}", exc_info=True)
        return render_template('error.html', error=str(e))

if __name__ == '__main__':
    logger.info("Starting Flask application...")
    app.run(debug=True, port=5000)
