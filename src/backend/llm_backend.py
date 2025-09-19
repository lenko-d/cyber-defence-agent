#!/usr/bin/env python3
"""
CDA Python Backend with LLM Integration
Provides advanced analysis and decision support using Large Language Models
"""

import json
import requests
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import socket
import threading
import time

class LLMBackend:
    def __init__(self, llm_api_url: str = "http://localhost:8000", api_key: str = None):
        self.llm_api_url = llm_api_url
        self.api_key = api_key
        self.logger = logging.getLogger(__name__)
        self.setup_logging()

        # Knowledge base for learned patterns
        self.knowledge_base = {}
        self.threat_patterns = []
        self.response_strategies = {}

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('llm_backend.log'),
                logging.StreamHandler()
            ]
        )

    def analyze_threat(self, observations: List[str]) -> Dict[str, Any]:
        """
        Use LLM to analyze potential threats from system observations
        """
        prompt = self._create_analysis_prompt(observations)

        try:
            response = self._query_llm(prompt)
            analysis = self._parse_llm_response(response)

            # Learn from this analysis
            self._learn_from_analysis(observations, analysis)

            return analysis
        except Exception as e:
            self.logger.error(f"Error analyzing threat: {e}")
            return {"threat_level": "unknown", "confidence": 0.0, "recommendations": []}

    def generate_response_plan(self, threat_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive response plan using LLM
        """
        prompt = self._create_response_prompt(threat_analysis)

        try:
            response = self._query_llm(prompt)
            plan = self._parse_response_plan(response)

            return plan
        except Exception as e:
            self.logger.error(f"Error generating response plan: {e}")
            return {"actions": [], "priority": "low", "estimated_time": 0}

    def predict_future_threats(self, historical_data: List[Dict]) -> List[Dict]:
        """
        Use LLM to predict potential future threats based on historical data
        """
        prompt = self._create_prediction_prompt(historical_data)

        try:
            response = self._query_llm(prompt)
            predictions = self._parse_predictions(response)

            return predictions
        except Exception as e:
            self.logger.error(f"Error predicting threats: {e}")
            return []

    def _create_analysis_prompt(self, observations: List[str]) -> str:
        """Create a prompt for threat analysis"""
        obs_text = "\n".join(f"- {obs}" for obs in observations)

        return f"""
You are an expert cybersecurity analyst. Analyze the following system observations for potential threats:

{obs_text}

Please provide:
1. Threat assessment (high/medium/low/none)
2. Confidence level (0-1)
3. Specific threats identified
4. Recommended immediate actions
5. Long-term security recommendations

Format your response as JSON with keys: threat_level, confidence, threats, immediate_actions, long_term_recommendations
"""

    def _create_response_prompt(self, threat_analysis: Dict[str, Any]) -> str:
        """Create a prompt for response planning"""
        return f"""
You are a cybersecurity incident response coordinator. Based on this threat analysis:

{json.dumps(threat_analysis, indent=2)}

Create a detailed response plan including:
1. Immediate containment actions
2. Investigation steps
3. Recovery procedures
4. Communication requirements
5. Timeline estimates

Format as JSON with keys: immediate_actions, investigation_steps, recovery_procedures, communication, timeline
"""

    def _create_prediction_prompt(self, historical_data: List[Dict]) -> str:
        """Create a prompt for threat prediction"""
        data_text = "\n".join(json.dumps(entry, indent=2) for entry in historical_data[-10:])  # Last 10 entries

        return f"""
Based on this historical threat data, predict potential future threats:

{data_text}

Provide predictions for the next 24 hours including:
1. Likely attack vectors
2. Potential targets
3. Recommended preventive measures
4. Risk levels

Format as JSON array of prediction objects
"""

    def _query_llm(self, prompt: str) -> str:
        """Query the LLM API"""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "prompt": prompt,
            "max_tokens": 1000,
            "temperature": 0.3
        }

        response = requests.post(
            f"{self.llm_api_url}/generate",
            headers=headers,
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            return response.json().get("text", "")
        else:
            raise Exception(f"LLM API error: {response.status_code}")

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response into structured data"""
        try:
            # Try to extract JSON from response
            start = response.find("{")
            end = response.rfind("}") + 1
            if start != -1 and end != -1:
                json_str = response[start:end]
                return json.loads(json_str)
        except:
            pass

        # Fallback parsing
        return {
            "threat_level": "medium" if "threat" in response.lower() else "low",
            "confidence": 0.5,
            "threats": ["Potential security issue detected"],
            "immediate_actions": ["Investigate further"],
            "long_term_recommendations": ["Monitor system closely"]
        }

    def _parse_response_plan(self, response: str) -> Dict[str, Any]:
        """Parse response plan from LLM"""
        try:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start != -1 and end != -1:
                json_str = response[start:end]
                return json.loads(json_str)
        except:
            pass

        return {
            "immediate_actions": ["Isolate affected systems", "Collect evidence"],
            "investigation_steps": ["Analyze logs", "Check for indicators of compromise"],
            "recovery_procedures": ["Restore from backup", "Patch vulnerabilities"],
            "communication": ["Notify security team", "Document incident"],
            "timeline": "4-6 hours"
        }

    def _parse_predictions(self, response: str) -> List[Dict]:
        """Parse predictions from LLM"""
        try:
            start = response.find("[")
            end = response.rfind("]") + 1
            if start != -1 and end != -1:
                json_str = response[start:end]
                return json.loads(json_str)
        except:
            pass

        return [{
            "timeframe": "next_24h",
            "attack_vector": "Unknown",
            "target": "System resources",
            "preventive_measures": ["Regular monitoring", "Update security patches"],
            "risk_level": "medium"
        }]

    def _learn_from_analysis(self, observations: List[str], analysis: Dict[str, Any]):
        """Learn from threat analysis to improve future detection"""
        threat_key = f"threat_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        self.knowledge_base[threat_key] = {
            "observations": observations,
            "analysis": analysis,
            "timestamp": datetime.now().isoformat()
        }

        # Update threat patterns
        if analysis.get("threat_level") in ["high", "medium"]:
            self.threat_patterns.extend(observations)

    def get_learned_patterns(self) -> List[str]:
        """Get patterns learned from previous analyses"""
        return list(set(self.threat_patterns))

    def save_knowledge_base(self, filename: str = "knowledge_base.json"):
        """Save the knowledge base to file"""
        with open(filename, 'w') as f:
            json.dump(self.knowledge_base, f, indent=2)

    def load_knowledge_base(self, filename: str = "knowledge_base.json"):
        """Load the knowledge base from file"""
        try:
            with open(filename, 'r') as f:
                self.knowledge_base = json.load(f)
        except FileNotFoundError:
            self.logger.info("Knowledge base file not found, starting with empty base")


class BackendServer:
    """HTTP server for the backend"""

    def __init__(self, backend: LLMBackend, host: str = "localhost", port: int = 8081):
        self.backend = backend
        self.host = host
        self.port = port
        self.server_socket = None
        self.running = False

    def start(self):
        """Start the backend server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        self.running = True
        self.logger = logging.getLogger(__name__)
        self.logger.info(f"Backend server started on {self.host}:{self.port}")

        server_thread = threading.Thread(target=self._serve_forever)
        server_thread.daemon = True
        server_thread.start()

    def stop(self):
        """Stop the backend server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

    def _serve_forever(self):
        """Main server loop"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
            except OSError:
                break  # Socket was closed
            except Exception as e:
                self.logger.error(f"Server error: {e}")

    def _handle_client(self, client_socket: socket.socket, address):
        """Handle individual client connections"""
        try:
            data = client_socket.recv(4096).decode('utf-8')
            if not data:
                return

            # Parse request (simple HTTP parsing)
            lines = data.split('\n')
            if lines:
                request_line = lines[0].strip()
                if request_line.startswith('POST'):
                    # Handle POST request
                    response = self._process_request(data)
                    client_socket.sendall(response.encode('utf-8'))

        except Exception as e:
            self.logger.error(f"Client handling error: {e}")
        finally:
            client_socket.close()

    def _process_request(self, request_data: str) -> str:
        """Process incoming requests"""
        try:
            # Extract JSON payload from request
            body_start = request_data.find('\r\n\r\n')
            if body_start != -1:
                json_data = request_data[body_start + 4:]
                request = json.loads(json_data)

                action = request.get('action')

                if action == 'analyze_threat':
                    observations = request.get('observations', [])
                    result = self.backend.analyze_threat(observations)
                elif action == 'generate_response':
                    threat_analysis = request.get('threat_analysis', {})
                    result = self.backend.generate_response_plan(threat_analysis)
                elif action == 'predict_threats':
                    historical_data = request.get('historical_data', [])
                    result = self.backend.predict_future_threats(historical_data)
                else:
                    result = {"error": "Unknown action"}

                return self._create_http_response(result)
            else:
                return self._create_http_response({"error": "Invalid request"})

        except Exception as e:
            self.logger.error(f"Request processing error: {e}")
            return self._create_http_response({"error": str(e)})

    def _create_http_response(self, data: Dict) -> str:
        """Create HTTP response"""
        json_response = json.dumps(data)
        return f"""HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(json_response)}\r\n\r\n{json_response}"""


if __name__ == "__main__":
    # Initialize backend
    backend = LLMBackend()
    backend.load_knowledge_base()

    # Start server
    server = BackendServer(backend)
    server.start()

    print("CDA LLM Backend started. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping backend...")
        server.stop()
        backend.save_knowledge_base()
        print("Backend stopped.")
