import unittest
import itertools

import ShSS
from polynomial import Polynomial

class TestShSSverify(unittest.TestCase):
    def test_one(self):
        test="15h93sLUi"
        share = ShSS.split(1,1,test)
        self.assertEqual(share[0][:-1],test)

class TestShSSdecoding(unittest.TestCase):
    def setUp(self):
        self.string = "Ah7g30LXaR2T"
        shares = ShSS.split(3,2,self.string)

        self.share0=shares[0]
        self.share1=shares[1]
        self.share2=shares[2]

    def test_unsplit(self):
        rec=ShSS.recover([self.share0,self.share1])
        self.assertEqual(self.string,rec)

        rec=ShSS.recover([self.share0,self.share2])
        self.assertEqual(self.string,rec)
        
        rec=ShSS.recover([self.share1,self.share2])
        self.assertEqual(self.string,rec)
        
        rec=ShSS.recover([self.share1,self.share0])
        self.assertEqual(self.string,rec)
        
        rec=ShSS.recover([self.share2,self.share0])
        self.assertEqual(self.string,rec)
        
        rec=ShSS.recover([self.share2,self.share1])
        self.assertEqual(self.string,rec)
        
    def test_singleshare(self):
        rec=ShSS.recover([self.share0])
        self.assertEqual(self.share0[:-1],rec)
        
    def test_dupshare(self):
        rec=ShSS.recover([self.share0,self.share0,self.share1])
        self.assertEqual(self.string,rec)
        
class TestShSSpasswdDecoding(unittest.TestCase):
    def setUp(self):
        self.string="5KhyfSnsmQ6PSkx81Bw6vWqgdiJune4v1fxytuT6RJBu33TxQWN"
        shares = ShSS.split(3,2,self.string,"password")

        self.share0=shares[0]
        self.share1=shares[1]
        self.share2=shares[2]
        
    def test_password_Recovery(self):
        rec=ShSS.recover([self.share0,self.share1],"password")
        self.assertEqual(self.string,rec)
        
class TestLargenumShares(unittest.TestCase):
    def setUp(self):
        self.string="5KhyfSnsmQ6PSkx81Bw6vWqgdiJune4v1fxytuT6RJBu33TxQWN"
        shares = ShSS.split(16,2,self.string,)

        self.share0=shares[15]
        self.share1=shares[12]
    
    def test_largeshares(self):
        rec=ShSS.recover([self.share0,self.share1])
        self.assertEqual(self.string,rec)
if __name__ == "__main__":
    unittest.main()
