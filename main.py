import base64
import os
import json
import hashlib
import websocket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import curl_cffi.requests as requests
import threading
import queue
import time
import random
import colorama
from colorama import Fore, Style
import datetime
import ctypes

# Initialize colorama for Windows compatibility
colorama.init()


banner = '''
                ████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗     ██████╗██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ███████╗██████╗ 
                ╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║    ██╔════╝██║  ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝██╔══██╗
                   ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║    ██║     ███████║███████║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝
                   ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║    ██║     ██╔══██║██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗
                   ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║    ╚██████╗██║  ██║██║  ██║██║ ╚████║╚██████╔╝███████╗██║  ██║
                   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝ 
'''

def get_timestamp():
    """Return formatted timestamp with colored brackets and time in HH:MM:SS."""
    now = datetime.datetime.now()
    return f"{Style.BRIGHT}{Fore.WHITE}[{Fore.LIGHTBLACK_EX}{now.strftime('%H:%M:%S')}{Fore.WHITE}]{Style.RESET_ALL}"

def set_terminal_title(title):
    """Set terminal window title (Windows-compatible)."""
    try:
        ctypes.windll.kernel32.SetConsoleTitleW(title)
    except Exception:
        pass

class Main:
    def __init__(self, token: str, proxy: dict = None) -> None:
        self.token = token
        self.sess = requests.Session(impersonate="chrome124")  # Windows compatible
        self.headers = {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'authorization': self.token,
            'content-type': 'application/json',
            'origin': 'https://discord.com',
            'referer': 'https://discord.com/channels/@me',
            'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'x-debug-options': 'bugReporterEnabled',
            'x-discord-locale': 'en-US',
            'x-discord-timezone': 'Asia/Tokyo',
            'x-super-properties': 'eyJvcyI6IldpbmRvd3MiLCJicm93c2VyIjoiQ2hyb21lIiwiZGV2aWNlIjoiIiwic3lzdGVtX2xvY2FsZSI6ImVuLVVTIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzMS4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTMxLjAuMC4wIiwib3NfdmVyc2lvbiI6IjEwIiwicmVmZXJlciI6IiIsInJlZmVycmluZ19kb21haW4iOiIiLCJyZWZlcnJlcl9jdXJyZW50IjoiIiwicmVmZXJyaW5nX2RvbWFpbl9jdXJyZW50IjoiIiwicmVsZWFzZV9jaGFubmVsIjoic3RhYmxlIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzgwMjEzLCJjbGllbnRfZXZlbnRfc291cmNlIjpudWxsfQ=='
        }
        self.sess.headers.update(self.headers)
        self.ws_url = "wss://remote-auth-gateway.discord.gg/?v=2"
        self.proxy = proxy
        if proxy:
            self.sess.proxies = proxy

    def create_kp(self) -> tuple:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        return priv.public_key(), priv
    
    def encode_pk(self, pub) -> str:
        return base64.b64encode(pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode('utf-8')
    
    def proc_nonce(self, nonce_data: str, priv) -> str:
        data = json.loads(nonce_data)
        enc_nonce = base64.b64decode(data["encrypted_nonce"])
        
        dec_nonce = priv.decrypt(
            enc_nonce,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return json.dumps({
            "op": "nonce_proof",
            "proof": base64.urlsafe_b64encode(hashlib.sha256(dec_nonce).digest()).rstrip(b"=").decode(),
        })
    
    def decrypt(self, enc_data: str, priv) -> bytes:
        if not enc_data:
            return None
        
        payload = base64.b64decode(enc_data)
        return priv.decrypt(
            payload,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def handshake(self, fp: str) -> None:
        r = self.sess.post(
            "https://discord.com/api/v9/users/@me/remote-auth", 
            json={'fingerprint': fp}
        ).json()
        
        token = r.get('handshake_token')
        if token:
            self.sess.post(
                "https://discord.com/api/v9/users/@me/remote-auth/finish", 
                json={'handshake_token': token}
            )
    
    def logout(self, token: str) -> bool:
        hdrs = self.headers.copy()
        hdrs['authorization'] = token
        self.sess.headers.update(hdrs)
        
        r = self.sess.post(
            'https://discord.com/api/v9/auth/logout',
            json={'provider': None, 'voip_provider': None}
        )
        return r.status_code == 204
    
    def clone(self) -> str:
        try:
            ws_kwargs = {
                "header": [
                    f"Authorization: {self.token}",
                    "Origin: https://discord.com"
                ]
            }
            if self.proxy:
                proxy_url = self.proxy.get("http", "").replace("http://", "")
                ws_kwargs["http_proxy_host"] = proxy_url.split("@")[1].split(":")[0]
                ws_kwargs["http_proxy_port"] = int(proxy_url.split(":")[1])
                ws_kwargs["http_proxy_auth"] = tuple(proxy_url.split("@")[0].split(":"))
            
            ws = websocket.create_connection(self.ws_url, **ws_kwargs)
            
            ws.recv()  # Initial response
            
            pub, priv = self.create_kp()
            enc_key = self.encode_pk(pub)
            
            ws.send(json.dumps({"op": "init", "encoded_public_key": enc_key}))
            
            nonce = ws.recv()
            if not nonce:
                ws.close()
                return None, "Empty nonce response"
            proof = self.proc_nonce(nonce, priv)
            ws.send(proof)
            
            fp_response = ws.recv()
            if not fp_response:
                ws.close()
                return None, "Empty fingerprint response"
            fp_data = json.loads(fp_response)
            fp = fp_data.get("fingerprint")
            if not fp:
                ws.close()
                return None, "No fingerprint in response"
            
            self.handshake(fp)
            
            user_response = ws.recv()
            if not user_response:
                ws.close()
                return None, "Empty user payload response"
            user_data = json.loads(user_response)
            enc_user = user_data.get("encrypted_user_payload")
            if enc_user:
                self.decrypt(enc_user, priv)
            
            ticket_response = ws.recv()
            if not ticket_response:
                ws.close()
                return None, "Empty ticket response"
            ticket_data = json.loads(ticket_response)
            ticket = ticket_data.get("ticket")
            if not ticket:
                ws.close()
                return None, "No ticket in response"
            
            # Retry login request up to 3 times
            for attempt in range(3):
                login_r = self.sess.post(
                    "https://discord.com/api/v9/users/@me/remote-auth/login", 
                    json={"ticket": ticket}
                )
                
                if login_r.status_code == 429:
                    if attempt < 2:
                        time.sleep(2)
                        continue
                    ws.close()
                    return None, "Rate limit exceeded"
                
                try:
                    r_data = login_r.json()
                except ValueError:
                    if attempt < 2:
                        time.sleep(2)
                        continue
                    ws.close()
                    return None, "Invalid response from server"
                
                if "captcha_key" in r_data or r_data.get("message", "").lower().find("captcha") != -1:
                    ws.close()
                    return None, "Captcha detected"
                
                enc_token = r_data.get("encrypted_token")
                if enc_token:
                    break
                if attempt < 2:
                    time.sleep(2)
            
            if not enc_token:
                ws.close()
                return None, "No encrypted token in response"
            
            ws.close()
            
            new_token = self.decrypt(enc_token, priv)
            if not new_token:
                return None, "Failed to decrypt new token"
                
            return new_token.decode('utf-8'), None
            
        except json.JSONDecodeError:
            return None, "Invalid response format"
        except websocket.WebSocketException:
            return None, "WebSocket connection failed"
        except Exception:
            return None, "Unexpected error"

def load_config(file_path: str = "config.json") -> dict:
    """Load configuration from config.json."""
    try:
        with open(file_path, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Error: config.json not found. Using default config.{Style.RESET_ALL}")
        return {"max_threads": 1, "proxyless": True, "avoid_rate_limit": True, "sleep_seconds": 2.0}
    except Exception:
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Error: Failed to load config.json. Using default config.{Style.RESET_ALL}")
        return {"max_threads": 1, "proxyless": True, "avoid_rate_limit": True, "sleep_seconds": 2.0}

def read_proxies(file_path: str = "proxies.txt") -> list:
    """Read proxies from proxies.txt in user:pass@ip:port format."""
    try:
        with open(file_path, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
        return proxies
    except FileNotFoundError:
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Error: proxies.txt not found{Style.RESET_ALL}")
        return []
    except Exception:
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Error: Failed to read proxies.txt{Style.RESET_ALL}")
        return []

def format_proxy(proxy: str) -> dict:
    """Format a proxy string into a dict for HTTP and WebSocket."""
    try:
        user_pass, ip_port = proxy.split("@")
        return {
            "http": f"http://{user_pass}@{ip_port}",
            "https": f"http://{user_pass}@{ip_port}"
        }
    except Exception:
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Error: Invalid proxy format: {proxy}{Style.RESET_ALL}")
        return None

def validate_token(token: str, proxy: dict = None) -> bool:
    """Validate a token by making a simple API call."""
    try:
        headers = {"Authorization": token}
        sess = requests.Session(impersonate="chrome124")
        if proxy:
            sess.proxies = proxy
        response = sess.get("https://discord.com/api/v9/users/@me", headers=headers)
        return response.status_code == 200
    except Exception:
        return False

def read_tokens(file_path: str = "tokens.txt") -> list:
    """Read tokens from a file, one per line."""
    try:
        with open(file_path, 'r') as f:
            tokens = [line.strip() for line in f if line.strip()]
        return tokens
    except FileNotFoundError:
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Error: tokens.txt not found{Style.RESET_ALL}")
        return []
    except Exception:
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Error: Failed to read tokens.txt{Style.RESET_ALL}")
        return []

def save_token(original_token: str, new_token: str, file_path: str = "output.txt") -> None:
    """Save the new token to a file."""
    try:
        with open(file_path, 'a') as f:
            f.write(f"{new_token}\n")
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.GREEN}Saved new token to {file_path}{Style.RESET_ALL}")
    except Exception:
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Error: Failed to save token to {file_path}{Style.RESET_ALL}")

def process_token(token: str, results: queue.Queue, proxies: list, proxyless: bool) -> None:
    """Process a single token and store the result in the queue."""
    try:
        proxy = None
        if not proxyless and proxies:
            proxy_str = random.choice(proxies)
            proxy = format_proxy(proxy_str)
            if not proxy:
                proxy = None
        
        if not validate_token(token, proxy):
            print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Error: Invalid token: {token}{Style.RESET_ALL}")
            results.put((token, None, False))
            return
        
        dc = Main(token, proxy)
        new_token, error = dc.clone()
        
        if new_token and dc.logout(token):
            print(f"{get_timestamp()} {Style.BRIGHT}{Fore.GREEN}Success: {token[:23]}****** ---> {new_token[:23]}****** {Style.RESET_ALL}")
            save_token(token, new_token)
            results.put((token, new_token, True))
        else:
            print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Failed: {token} ({error}){Style.RESET_ALL}")
            results.put((token, None, False))
    except Exception:
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Error: Failed to process {token}{Style.RESET_ALL}")
        results.put((token, None, False))

def run() -> list:
    start_time = time.time()
    set_terminal_title("Token Changer - Elapsed: 0.00s")
    
    config = load_config()
    max_threads = config.get("max_threads", 1)
    proxyless = config.get("proxyless", True)
    avoid_rate_limit = config.get("avoid_rate_limit", True)
    sleep_seconds = config.get("sleep_seconds", 2.0)
    
    proxies = read_proxies() if not proxyless else []
    if not proxyless and not proxies:
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.YELLOW}Warning: proxyless is false but no proxies found. Running without proxies.{Style.RESET_ALL}")
        proxyless = True
    
    tokens = read_tokens()
    if not tokens:
        print(f"{get_timestamp()} {Style.BRIGHT}{Fore.RED}Error: No tokens to process{Style.RESET_ALL}")
        return []

    results = queue.Queue()
    threads = []

    print(f"                                      {Style.BRIGHT}{Fore.GREEN}Materials Found : {len(tokens)} Tokens And {max_threads} Threads...{Style.RESET_ALL}")

    # Create and start threads
    for token in tokens:
        while threading.active_count() >= max_threads + 1:  # +1 for main thread
            time.sleep(0.1)  # Brief wait to avoid busy loop
        thread = threading.Thread(target=process_token, args=(token, results, proxies, proxyless))
        threads.append(thread)
        thread.start()
        if avoid_rate_limit:
            time.sleep(sleep_seconds)  # Configurable delay to avoid rate limits
        
        # Update terminal title with elapsed time
        elapsed = time.time() - start_time
        set_terminal_title(f"Token Changer - Elapsed: {elapsed:.2f}s")

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Collect results
    output = []
    while not results.empty():
        output.append(results.get())

    # Print summary
    successes = sum(1 for _, _, success in output if success)
    elapsed = time.time() - start_time
    print(f"{get_timestamp()} {Style.BRIGHT}{Fore.WHITE}Completed: {successes}/{len(tokens)} tokens processed successfully{Style.RESET_ALL}")
    print(f"{get_timestamp()} {Style.BRIGHT}{Fore.WHITE}Elapsed time: {elapsed:.2f} seconds{Style.RESET_ALL}")
    
    # Final terminal title update
    set_terminal_title(f"Token Changer - Elapsed: {elapsed:.2f}s")
    time.sleep(100)
    
    return output

print(f"{Fore.BLUE}{banner}{Fore.RESET}")

if __name__ == "__main__":
    run()