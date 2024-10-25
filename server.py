from flask import Flask, request, jsonify, render_template
import hashlib
import time
import base64

app = Flask(__name__)

# Configuration
FLAG = "FLAG{P4ck3t_Sn1ff1ng_1s_Fun!}"
INITIAL_KEY = "start_here"
FLAG_SEGMENTS = [FLAG[i:i+8] for i in range(0, len(FLAG), 8)]

# Store for session management
sessions = {}

def encode_data(data, segment_num):
    """Encode data differently for each segment to encourage packet inspection"""
    if segment_num % 3 == 0:
        # Base64 encoding
        return base64.b64encode(data.encode()).decode()
    elif segment_num % 3 == 1:
        # Reverse string
        return data[::-1]
    else:
        # ROT13-like substitution
        return data.translate(str.maketrans(
            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
        ))

@app.route('/')
def index():
    return render_template('index.html', initial_key=INITIAL_KEY)

@app.route('/api/segment/<int:segment_num>', methods=['POST'])
def get_segment(segment_num):
    if segment_num < 0 or segment_num >= len(FLAG_SEGMENTS):
        return jsonify({'error': 'Invalid segment number'}), 400
    
    # Hidden flag segments in response headers for packet sniffing practice
    response = jsonify({
        'message': 'Inspect the network traffic carefully...',
        'segment_num': segment_num,
        'total_segments': len(FLAG_SEGMENTS)
    })
    
    # Add encoded flag data in custom headers
    segment = FLAG_SEGMENTS[segment_num]
    encoded_segment = encode_data(segment, segment_num)
    
    response.headers['X-Debug-Info'] = f'Segment {segment_num}'
    response.headers['X-Encoded-Data'] = encoded_segment
    response.headers['X-Encoding-Type'] = f'type_{segment_num % 3}'
    
    # Add some decoy headers to make it interesting
    response.headers['X-Server-Time'] = str(int(time.time()))
    response.headers['X-Request-ID'] = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    
    return response

@app.route('/api/hint', methods=['GET'])
def get_hint():
    """Endpoint that reveals encoding information in network traffic"""
    encoding_info = {
        'type_0': 'base64',
        'type_1': 'reverse',
        'type_2': 'substitution'
    }
    return jsonify(encoding_info)

if __name__ == '__main__':
    app.run(debug=True)