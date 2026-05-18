import http.server
import json
import math
import csv
import os
import statistics

# ── Simple built-in ML Detection Engine ──

class ZeroDayDetector:
    def __init__(self):
        self.stats = {}
        self.trained = False

    def train(self, filepath):
        print("[*] Loading dataset...")
        numeric_cols = [
            'duration', 'src_bytes', 'dst_bytes',
            'count', 'srv_count', 'serror_rate', 'rerror_rate'
        ]
        data = {col: [] for col in numeric_cols}

        try:
            with open(filepath, 'r') as f:
                first_line = f.readline().strip()

            # Check if ARFF format
            if '@relation' in first_line.lower():
                rows = []
                in_data = False
                with open(filepath, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line.lower() == '@data':
                            in_data = True
                            continue
                        if in_data and line:
                            rows.append(line.split(','))

                col_map = {
                    'duration': 0, 'src_bytes': 4,
                    'dst_bytes': 5, 'count': 22,
                    'srv_count': 23, 'serror_rate': 24,
                    'rerror_rate': 26
                }
                label_idx = 41

                for row in rows:
                    if len(row) > label_idx:
                        for col, idx in col_map.items():
                            try:
                                data[col].append(float(row[idx]))
                            except:
                                data[col].append(0.0)
            else:
                col_map = {
                    'duration': 0, 'src_bytes': 4,
                    'dst_bytes': 5, 'count': 22,
                    'srv_count': 23, 'serror_rate': 24,
                    'rerror_rate': 26
                }
                with open(filepath, 'r') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) > 26:
                            for col, idx in col_map.items():
                                try:
                                    data[col].append(float(row[idx]))
                                except:
                                    data[col].append(0.0)

            # Calculate mean and std for each column
            for col in numeric_cols:
                if data[col]:
                    mean = statistics.mean(data[col])
                    try:
                        std = statistics.stdev(data[col])
                    except:
                        std = 1.0
                    self.stats[col] = {
                        'mean': mean,
                        'std': std if std > 0 else 1.0
                    }

            self.trained = True
            print(f"[✓] Trained on {len(data['duration'])} records!")

        except Exception as e:
            print(f"[!] Training error: {e}")
            # Use default stats if training fails
            self.stats = {
                'duration':    {'mean': 0.5,   'std': 10.0},
                'src_bytes':   {'mean': 500.0,  'std': 2000.0},
                'dst_bytes':   {'mean': 2000.0, 'std': 8000.0},
                'count':       {'mean': 50.0,   'std': 100.0},
                'srv_count':   {'mean': 50.0,   'std': 100.0},
                'serror_rate': {'mean': 0.05,   'std': 0.2},
                'rerror_rate': {'mean': 0.05,   'std': 0.2},
            }
            self.trained = True

    def z_score(self, value, col):
        if col not in self.stats:
            return 0.0
        mean = self.stats[col]['mean']
        std  = self.stats[col]['std']
        return abs((value - mean) / std)

    def detect(self, traffic):
        # ── Rule-based known attack detection
        attack_score = 0
        reasons = []

        # DoS patterns
        if traffic.get('serror_rate', 0) > 0.8:
            attack_score += 40
            reasons.append('High SYN error rate (DoS)')

        if traffic.get('count', 0) > 400:
            attack_score += 30
            reasons.append('Very high connection count')

        if (traffic.get('src_bytes', 0) == 0 and
            traffic.get('dst_bytes', 0) == 0 and
            traffic.get('count', 0) > 100):
            attack_score += 30
            reasons.append('Zero bytes with high count (scan)')

        # Port scan patterns
        if (traffic.get('rerror_rate', 0) > 0.8 and
            traffic.get('count', 0) > 100):
            attack_score += 35
            reasons.append('High reject rate (port scan)')

        if traffic.get('flag') in ['S0', 'REJ', 'RSTO', 'RSTR']:
            attack_score += 20
            reasons.append(f"Suspicious flag: {traffic.get('flag')}")

        # ── Anomaly detection using Z-scores
        anomaly_score = 0
        check_fields = [
            'duration', 'src_bytes', 'dst_bytes',
            'count', 'srv_count', 'serror_rate', 'rerror_rate'
        ]
        for field in check_fields:
            val = traffic.get(field, 0)
            try:
                z = self.z_score(float(val), field)
                if z > 3:
                    anomaly_score += 15
                elif z > 2:
                    anomaly_score += 8
            except:
                pass

        # ── Results
        rf_attack  = attack_score >= 40
        iso_anomaly = anomaly_score >= 30

        confidence = min(attack_score, 99)

        if rf_attack:
            zero_day_risk = 'CONFIRMED ATTACK'
        elif iso_anomaly:
            zero_day_risk = 'HIGH'
        else:
            zero_day_risk = 'LOW'

        return {
            'rf_result':     'ATTACK ⚠️' if rf_attack   else 'Normal ✅',
            'iso_result':    'ANOMALY ⚠️' if iso_anomaly else 'Normal ✅',
            'confidence':    f'{confidence}%',
            'zero_day_risk': zero_day_risk,
            'reasons':       reasons if reasons else ['No threats detected']
        }


# ── Initialize and train detector ──
detector = ZeroDayDetector()
if os.path.exists('KDDTrain+.csv'):
    detector.train('KDDTrain+.csv')
else:
    print("[!] Dataset not found — using default stats")
    detector.trained = True
    detector.stats = {
        'duration':    {'mean': 0.5,   'std': 10.0},
        'src_bytes':   {'mean': 500.0,  'std': 2000.0},
        'dst_bytes':   {'mean': 2000.0, 'std': 8000.0},
        'count':       {'mean': 50.0,   'std': 100.0},
        'srv_count':   {'mean': 50.0,   'std': 100.0},
        'serror_rate': {'mean': 0.05,   'std': 0.2},
        'rerror_rate': {'mean': 0.05,   'std': 0.2},
    }


# ── Web Server ──
class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Silence default logs

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html_path = os.path.join('templates', 'index.html')
            with open(html_path, 'rb') as f:
                self.wfile.write(f.read())

    def do_POST(self):
        if self.path == '/analyze':
            length = int(self.headers['Content-Length'])
            body   = self.rfile.read(length)
            data   = json.loads(body)

            result = detector.detect(data)

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())


# ── Start Server ──
PORT = 5000
print(f"[✓] Zero-Day Detector running!")
print(f"[✓] Open your browser and go to: http://127.0.0.1:{PORT}")
print(f"[!] Press CTRL+C to stop\n")

server = http.server.HTTPServer(('127.0.0.1', PORT), Handler)
server.serve_forever()