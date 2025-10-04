1.
Split-piping stderr and stdout

In this challenge, you have:/challenge/hack: this produces data on stdout and stderr /challenge/the: you must redirect hack's stderr to this program /challenge/planet: you must redirect hack's stdout to this program Go get the flag!
Solve

I used pipe operator to duplicate the output of the initial command into the file descriptor 2 of /challenge/the which stores the stderr in it.
image


<img width="620" height="89" alt="image" src="https://github.com/user-attachments/assets/7a278be4-bc57-4c25-a824-c3366a0604c6" />

Multiple globs

We put a few happy, but diversely-named files in /challenge/files. Go cd there and run /challenge/run, providing a single argument: a short (3 characters or less) globbed word with two * globs in it that covers every word that contains the letter p.
Solve
I used file globbing techniques to cover all the cases according to the question to get the flag

<img width="796" height="200" alt="image" src="https://github.com/user-attachments/assets/8cb2cf12-25cf-47ee-aa58-8becaf52b6e2" />

Snooping on Configs

Zardus stores his key in .bashrc. Can you steal the key and get the flag?

I found that Zardus’s ~/.bashrc was world-readable and contained the line FLAG_GETTER_API_KEY=sk-XXXYYYZZZ. By reading it and running flag_getter --key $(awk -F= '/FLAG_GETTER_API_KEY/{print $2}' /home/zardus/.bashrc), I retrieved the flag pwn.college{HACKED}.

<img width="711" height="88" alt="image" src="https://github.com/user-attachments/assets/02bd1d71-ed74-4310-93b4-6679478ce7c6" />

<img width="687" height="94" alt="image" src="https://github.com/user-attachments/assets/11e8cb07-df1b-4ff4-aaad-518412593b11" />

3.1 
import string, sys
A = string.ascii_uppercase
M = 26

def to_nums(s): return [A.index(c) for c in s.upper() if c.isalpha()]
def to_text(nums): return ''.join(A[n % M] for n in nums)
def chunks(lst): 
    if len(lst)%2: lst = lst + [A.index('X')]
    return [lst[i:i+2] for i in range(0,len(lst),2)]

def modinv(a):
    a %= M
    for x in range(M):
        if (a*x) % M == 1: return x
    return None

def det(k): return (k[0][0]*k[1][1]-k[0][1]*k[1][0])%M
def inv_key(k):
    d = modinv(det(k))
    if d is None: return None
    return [[( d*k[1][1])%M, (-d*k[0][1])%M],
            [(-d*k[1][0])%M, ( d*k[0][0])%M]]

def encrypt(k,pt):
    n = to_nums(pt)
    out=[]
    for p in chunks(n):
        out += [ (k[0][0]*p[0]+k[0][1]*p[1])%M, (k[1][0]*p[0]+k[1][1]*p[1])%M ]
    return to_text(out)

def decrypt(k,ct):
    ik = inv_key(k)
    if ik is None: raise ValueError("Key not invertible")
    n = to_nums(ct)
    out=[]
    for p in chunks(n):
        out += [ (ik[0][0]*p[0]+ik[0][1]*p[1])%M, (ik[1][0]*p[0]+ik[1][1]*p[1])%M ]
    return to_text(out)

if __name__=="__main__":
    if len(sys.argv)<4:
        print("usage: python hill.py encrypt|decrypt KEY(4letters) TEXT")
        sys.exit(1)
    mode, keytxt, text = sys.argv[1].lower(), sys.argv[2], " ".join(sys.argv[3:])
    knums = to_nums(keytxt)
    if len(knums)!=4: raise SystemExit("KEY must be 4 letters")
    key = [[knums[0],knums[1]],[knums[2],knums[3]]]
    if mode=="encrypt": print(encrypt(key,text))
    elif mode=="decrypt": print(decrypt(key,text))
    else: print("mode must be encrypt or decrypt")


3.3 dingpadding

3.4 G I F I G D G A B
