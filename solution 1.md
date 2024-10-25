# Enhanced Packet Sniffing Challenge - Complete Solution

## Challenge Overview
The challenge involves intercepting and analyzing HTTP traffic to find hidden flag segments in response headers, with an additional layer of complexity involving dynamic page titles and their corresponding hashes.

## Tools Required
- Browser Developer Tools or
- Burp Suite or
- Python with requests library
- Base64 decoder
- MD5 hash calculator (optional)
- (Optional) Wireshark

### Step 1: Initial Reconnaissance
1. Open Browser Developer Tools (F12)
2. Go to the Network tab
3. Notice that the page title changes periodically between:
   - Network Detective Agency
   - Packet Analysis Hub
   - Traffic Inspection Central
   - Wireshark Warriors
   - Protocol Investigation Unit
4. Click the "Generate Traffic" button on the webpage
5. Observe the POST request to `/api/segment/0`

### Step 2: Analyzing Response Headers
For each request, we find four important headers:
- `X-Encoded-Data`: Contains the encoded flag segment
- `X-Encoding-Type`: Indicates the encoding method (type_0, type_1, or type_2)
- `X-Debug-Info`: Shows which segment number we're looking at
- `X-Page-Title-Hash`: Contains MD5 hash of the current page title (first 8 characters)

### Step 3: Understanding the Encoding Pattern
Make a GET request to `/api/hint` to understand the encoding types:
```json
{
    "type_0": "base64",
    "type_1": "reverse",
    "type_2": "substitution",
    "extra": "Look for connections between headers and what you see..."
}
```

### Step 4: Title Hash Verification (New Component)
1. Note down the current page title
2. Calculate its MD5 hash:
   ```python
   import hashlib
   title = "Network Detective Agency"
   hash = hashlib.md5(title.encode()).hexdigest()[:8]
   ```
3. Compare with `X-Page-Title-Hash` header
4. Verify that the hash changes with the title rotation

### Step 5: Manual Decoding Process
For each segment:

1. **Segment 0** (Base64):
   - X-Encoded-Data: `RkxBR3tQNA==`
   - Decode using base64 → `FLAG{P4`

2. **Segment 1** (Reverse):
   - X-Encoded-Data: `ff1nS_kc`
   - Reverse the string → `ck_Sn1ff`

3. **Segment 2** (Substitution):
   - X-Encoded-Data: `1at_1f_Sha`
   - Apply ROT13 substitution → `1ng_1s_Fun`

4. **Segment 3** (Base64):
   - X-Encoded-Data: `IXw==`
   - Decode using base64 → `!}`

### Step 6: Combining the Flag
Combining all segments: `FLAG{P4ck_Sn1ff1ng_1s_Fun!}`

