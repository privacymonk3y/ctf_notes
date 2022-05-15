# Percival

This challenge was pretty neat. I didn't solve it during the event but kept at it and with a little nudge from the author I was able to find the peace I was missing.
I'll walk through how I approached this challenge and how I finally figured out how to solve it.

### Files

```plaintext
pcap file: moxa_login.pcapng
```

Starting this challenge you are given the moxa_login pcap file.
Opening this in wireshark,

*picture holder*

You can see a lot of TCP and HTTP protocols here. If we follow the tcp stream and goto Stream 7 we can see clear text of the login and welcome screen.
Hardcoded into the html is the first half of the flag. `Welcome! DawgCTF{enc0ding`

*picture holder*

After this I went to file -> export objects -> html.
There are many files here so I clicked **Save All**

I first loaded up apache after renaming the files.
The mains ones being...

```plaintext
loginframe.html
home.html
index.html
submission.txt (just what I named this file)
```

home.html = welcome screen after login. This has the hardcoded flag / username.
loginframe.html = This contains the portion of the script used to encode the username/password.
index.html = is the psudo login page. It also shares the start of the script to encode the username/password.
submission.txt = the post command with encoded username/password, and the FakeChallenge cookie value.

What I ended up doing was taking both script blocks from login/index and putting them into a single .js file.
I removed any of the strings that matched `window.loginframe.` so the script would be contained in the single file.
I had never worked with .js or nodejs, this was a learning in progress lol. (One of the more interesting parts to this challenge)
I quickly found how console.log() worked so I could interact with the script and started to reverse what it was doing.

**Where I cost myself loads of time and pain**

*Jumping ahead to the part I didn't solve during the CTF but after with a nudge from the creator.*

So, in converting the files into one script I made a big mistake of changing this line...

`md = window.loginframe.SHA256(theform.FakeChallenge.value);`

from index.html to:

`md = '1932836BC9FA6984B77B4F99A86A4F9F6261A9540D6032746B27F4CFF5CBD4D7';`

This was the source of my trouble and pain. If I took a bit more time to read the code I would have seen what this function was doing.
The problem here is that the SHA256 function is a sha256sum function. It takes the FakeChallenge cookie and runs the sha256sum to give the REAL md value.
Because I didn't have this I was never able to reverse the known username/password, but still managed to create and reverse my own user/password.
Boy was that frustrating!

**Back to the method and reversing the script**

During my play with apache I ran burp. I could see that the clear text information wasn't being sent but first a client side encoding happened.
Then you ended up with something simular to the data in the submission.txt file.

```plaintext
account=e94976a41b106d0fe468a1a48031cfa8&password=8c1564ad3b365204f537adfa99&FakeChallenge=1932836BC9FA6984B77B4F99A86A4F9F6261A9540D6032746B27F4CFF5CBD4D7&csrf_token=6uqFw4XyJQFxHPdI
```

The reason for this is because of this code:

```js
function setInfo()
{
    var theform = document.account_password_form;
	var account_value = theform.account.value;
	theform.account.value = SetSHA256(theform, account_value);
	theform.password.value = SetSHA256(theform, theform.password.value);
	theform.submit();
	theform.account.value = account_value;
}
```

This calls on the SetSHA256 function:

```js
function SetSHA256(theform, raw_data){
	var hex_h = "0123456789abcdef";
	var md, p, q, m ,n, i;
	var p="";
	var sha256_data="";

	md = window.loginframe.SHA256(theform.FakeChallenge.value);
	for (i = 0; i < raw_data.length; i++)
	{
		q = window.loginframe.ascii.lastIndexOf(raw_data.charAt(i));
		p += q.toString(16);
	}
	for (i = 0; i < p.length; i++)
	{
		m = hex_h.indexOf(p.charAt(i));
		if (i >= md.length)
			n = hex_h.indexOf(md.charAt(i%md.length));
		else
			n = hex_h.indexOf(md.charAt(i));
		sha256_data += hex_h.charAt(window.loginframe.xor(m,n));
	}
	return sha256_data;
```

So, I used the console.log() to break down what was going on here.
The short story is, the md value is the sha256sum of the FakeChallenge cookie.
q = the last index of the plaintext character of variable ascii.

```js
var ascii="01234567890123456789012345678901" +
" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ"+
"[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
```

p = returns number object in base 16 here.

Then it goes in a loop for the length of the raw_data input.
M = the index of the p character in then hex_h variable
N = the i (or loop count) of the md char in the hex_h variable.
sha256_data = this function is a xor of m,n and charat hex_h variable.

This is where the attack comes into play. We can reverse the xor because we know what the value of the N is.
It's the sha256sum of the md (FakeChallenge cookie). Knowing this let's us use the xor against the encoded text to find the M value and reverse the entire process.

I rewrote the problem in python and this was the final solution.

```python
#!/usr/bin/env python3
import binascii

ascii_list = "01234567890123456789012345678901 !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

hex_h = "0123456789abcdef"
md = 'ad2801c358442b748106c294e458a1cfb08ef87365f4814568fa28ffff07d4fc'
encoded_string = '8c1564ad3b365204f537adfa99'
decoded_hex = ''


m = []
n = []
# Xor the encoded string to find out the value of M
for i in range(0, len(encoded_string), 1):
    n.append(hex_h.index(md[i]))
    unxor = hex_h.index(encoded_string[i])
    m.append(unxor ^ n[i])

for i in range(len(m)):
    decoded_hex += str(hex_h[m[i]])

# print(decoded_hex)
byte_array = bytearray.fromhex(decoded_hex)
print("DawgCTF{enc0ding" + byte_array.decode())
```
