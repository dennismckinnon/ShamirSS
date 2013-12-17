#Implementation of Shamir's Secret sharing for Bitcoin Private Keys
#Written up by Dennis McKinnon - dennis.r.mckinnon@gmail.com
#Polynomial class by Andrew Brown
#Use this code freely for whatever.
"""
Command line usage:
python Shss.py [-p "password"]{-s "n" "k" "Secret"/-sf "n" "k" "File"/-r "Shares"/ -rf "File"}

-p "password" - optional argument, followed immediately by the password to use
-s "n" "k" "Secret" - Specifies that "Secret" is to be split with n shares produced a minimum
                      of k being needed to successfully reconstruct the secret
-sf "n" "k" "File" - Same as -s but the secret is found in file "File"
-r "Shares" - Specifies that the "Shares" entered after -r (space separated) should be used to
              attempt recovery of the secret
-rf "File" - Same as -r except the shares are stored in the file "File" (One per line)
   
only one of (-s,-sf,-r,-rf) may be used. -p may be used with all arguments.

-------------------------------------------------------------------------------------------------
def split(n, k, secret{, password}):
n - Number of shares to produce, n>=k. if n<k, n is set to k
k - Threshold number of shares to reconstruct the secret
secret - The secret to be split. In this implementation this is a string of characters in
        base 58. This is so it works well with Bitcoin private addresses
password (optional) - ASCII string password which will be hashed and the result added to
                     the secret (one-time pad)
                          
Method implements Shamirs Secret sharing on a Field of integers mod 59. A sequence of
independent random polynomials are constructed for each character c of the secret such that
for each polynomial p, p(0)=c (more or less see b58conv and r58conv).
See http://en.wikipedia.org/wiki/Shamir's_Secret_Sharing for a detailed description of how
Shamir's Secret Sharing works

------------------------------------------------------------------------------------------------
def recover(shares[]{, password}):
shares[]- List of the secret shares
password (optional) - ASCII string password which will be hashed and the result added to
                      the secret (one-time pad) 
  
This method should reconstruct a secret from a certain number of shares
It will always assume enough shares are provided to reconstruct the secret
(By assuming the degree of the polynomial is one less then the number of shares)
   
What this means is if the threshold of reconstruction was k, and k'<k was provided
the output will not be guaranteed to be the secret
   
The probability that the k'<k shares will reconstruct the polynomial should be be
the probability that k'-1 shares determine the last which yeilds a constant 1/59
probability per character for a total probability that the secret is randomly revealed
as (1/59)^len(message). However it should be impossible for the attacker to know for sure
he has the secret (except by testing it)
  
Since the Field we are working with in finite, to brute-force this if you have k'=k-1 shares
you need to guess each of the 59 values for each character in the message, this is equivalent
to brute-forcing the original secret

-------------------------------------------------------------------------------------------------   
def b58conv(C):
C - Character in base 58 to be converted to an integer between 0 and 58
   
This is a helper function which performs the conversion of base 58 characters (plus 0) into
their integer equivalents
    
-------------------------------------------------------------------------------------------------
def r58conv(N):
N - Integer between 0 and 58 to be converted to a character in base 58
    
This performs the reverse operation to b58conv in that it will take integers mod 59 to their
equivalent in base 58 (plus 0)
"""
    
import os
import sys
import hashlib
from polynomial import Polynomial
from ffp import intmod
        
def split(n, k, secret, pword=""):
    #Intial Stuff
    intmod.set_base(59)
    if n < 0 or k < 0:
        raise ValueError("n and k must be positive")
    if k > n:
        print("Recovery threshold can not be greater then number of pieces")
        print("Setting n to k")
        n=k
    if k>58:
        raise ValueError("The recovery threshold can not be more than 58")
    if n>58:
        print("WARNING: If more then 58 shares are created they will not all")
        print("         have unique identifiers this might cause trouble when")
        print("         attempting to recover the secret")
    
        
    #Construct key, If no password is provided, key is set to all zeros
    if pword:
        tpw=hashlib.sha512(pword).digest()
        key=[intmod(ord(c)%59) for c in tpw]
    else:
        key=[intmod(0) for c in xrange(64)]
       
        
    seclen=len(secret)
    #Encode Secret as integers base 59
    secretint=[intmod((b58conv(s))) for s in secret]
    #Scramble Secret with password
    for i in xrange(seclen):
        secretint[i]=secretint[i]+key[i%64]
    
    polys=[]
    for i in xrange(seclen):
        temp=[]
        for j in xrange(k):
            if(j==k-1):
                temp.append(secretint[i])
            else:
                temp.append(intmod.rand())
        polys.append(Polynomial(temp))
    shares=[]
    for i in xrange(1,n+1):
        shares.append("".join(r58conv(polys[x].evaluate(intmod(i))) for x in xrange(seclen))+r58conv(i))
    return shares
    
def recover(shares, pword=""):
    #Intial Stuff
    intmod.set_base(59)
    #Construct key, If no password is provided, default password of "" is used
    if pword:
        tpw=hashlib.sha512(pword).digest()
        key=[intmod(ord(c)%59) for c in tpw]
    else:
        key=[intmod(0) for c in xrange(64)]
       
     
    #Catch errors Two keys for the same point
    lsh=len(shares)
    xs=[intmod(b58conv(shares[i][-1])) for i in xrange(lsh)]
    todel=[]
    for i in xrange(lsh-1):
        for j in xrange(i+1,lsh):
            if xs[i]==xs[j]:
                if j not in todel:
                    todel.append(j)
    d=0
    todel=sorted(todel,reverse=True)
    for  i in todel:
        del xs[i]
        del shares[i]
        d=d+1
    lsh=lsh-d
      
    #Construct the Lagrange Polynomials (These are the same for all elements)
    l=[]
    for i in xrange(lsh):
        lt=Polynomial(x0=intmod(1))
        for j in xrange(lsh):
            if i != j:
                if (xs[i]-xs[j])==intmod(0):
                    raise ValueError("Two of your keys are for identical points please remedy this")
                lt=lt*(Polynomial(x1=intmod(1),x0=-xs[j]))
                lt=lt//Polynomial(x0=(xs[i]-xs[j]))
        l.append(lt)
    #Reconstruct Secret (To best knowledge), Completes Lagrange integration for each character
    #Evaluates at 0 and converts into a base 58 character
    seclen=len(shares[0])-1
    rect=[]
    for i in xrange(seclen):
        p=Polynomial(x0=intmod(0))
        for j in xrange(lsh):
            p=p+Polynomial(x0=(b58conv(shares[j][i])))*l[j]
        rect.append(r58conv(p.evaluate(intmod(0))-key[i%64]))
    return "".join(rect)

def b58conv(C):
    alph=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z']
    if C in alph:
        return alph.index(C)
    return 101
    
def r58conv(N):
    alphabet=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f','g','h','i','j','k','m','n','o','p','q','r','s','t','u','v','w','x','y','z','A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z']
    return alphabet[N]
    
def main(args=None):
    #Handles calls from the command line
    if args is None:
        args=sys.argv
    intmod.set_base(59)
    psswd=""
    if "-h" in sys.argv:
        print __doc__
    if "-p" in sys.argv:
        psswd=sys.argv[sys.argv.index("-p")+1]
    if ("-r" in sys.argv) or ("-rf" in sys.argv):
        #recover mode
        if "-rf" in sys.argv:
            #If using file, shares are stored in files filebase(#).txt where # is in intmod
            file=sys.argv[sys.argv.index("-rf")+1]
            shares=[]

            if os.path.isfile(file):
                for line in open(file,"r"):
                    testshare=line.strip()
                    for c in testshare:
                        try:
                            temp=intmod(b58conv(c))
                        except:
                            print("\n-------------------------------------------------")
                            print("The File: "+file+" has illegal characters!")
                            print("Please ensure it only has alphanumeric characters")
                            print("and does not contain l, o, or O")
                            print("-------------------------------------------------\n")
                            raise ValueError
                    shares.append(testshare)
        else:
            #Manual input
            shares=[]
            for i in xrange(sys.argv.index("-r")+1,len(sys.argv)):
                testshare=sys.argv[i]
                if testshare[0]=="-":
                    break
                for c in testshare:
                    try:
                        temp=intmod(b58conv(c))
                    except:
                        print("\n-------------------------------------------------")
                        print("Your shares have illegal characters!")
                        print("Please ensure it only has alphanumeric characters")
                        print("and does not contain l, o, or O")
                        print("-------------------------------------------------\n")
                        raise ValueError
                shares.append(testshare)
        secret=recover(shares, psswd)
        print secret
    elif ("-s" in sys.argv) or ("-sf" in sys.argv):
        #secret splitting mode
        if "-sf" in sys.argv:
            ns=int(sys.argv[sys.argv.index("-sf")+1])
            ks=int(sys.argv[sys.argv.index("-sf")+2])
            
            sf=sys.argv[sys.argv.index("-sf")+3].split(".")
            fi=open(sf,"r")
            secret=fi.readline().strip()
            fi.close()
        else:
            ns=int(sys.argv[sys.argv.index("-s")+1])
            ks=int(sys.argv[sys.argv.index("-s")+2])
            secret=sys.argv[sys.argv.index("-s")+3]
        for c in secret:
            try:
                temp=intmod(b58conv(c))
            except:
                print("\n-------------------------------------------------")
                print("Your input secret has illegal characters!")
                print("Please ensure it only has alphanumeric characters")
                print("and does not contain l, o, or O")
                print("-------------------------------------------------\n")
                raise ValueError
        shares=split(ns, ks, secret, psswd)
        for x in shares:
            print x
    else:
        print "For help type \'python ShSS.py -h\'"    
    
if __name__ == "__main__":
    main()
