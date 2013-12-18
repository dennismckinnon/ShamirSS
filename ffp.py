# Adapted from code Copyright (c) 2010 Andrew Brown <brownan@cs.duke.edu, brownan@gmail.com>ddition in PF(59) is normal addition modulo 59"
# Copyright (c) 2013 Ryan Castellucci <code@ryanc.org>
# See LICENSE.txt for license terms

import os

class intmod(int):
    """Instances of this object are ints mod some number which is variable
    And set using the set_mod() function
    """
    # Maps integers to PF59int instances
    cache = {}
    # multiplicitive inverse table, modulo 59
    invtable = [None]
    base=False
    @classmethod
    def set_base(cls, modnum):
        cls.invtable=[None]
        intmod.base=modnum
        for i in xrange(1,modnum):
            for j in xrange(1,modnum):
                if((i*j)%modnum==1):
                    intmod.invtable.append(j)
                    break
#        print intmod.invtable
    def __new__(cls, value):
        # Check cache
        if not intmod.base:
            raise ValueError("The base can not be zero. Set a base with set_mod(base) first")
        try:
            return intmod.cache[value]
        except KeyError:
            if value > intmod.base  or value < 0:
                raise ValueError("Intmod elements are between 0 and {}. Cannot be {}".format(cls.base,value))
        newval = int.__new__(cls, value)
        cls.cache[int(value)] = newval
        return newval

    def __add__(a, b):
        "Addition in PF(59) is normal addition modulo 59"
        return intmod((int(a) + int(b)) % intmod.base)
    __radd__ = __add__

    def __sub__(a, b):
	"Subtraction in PF(59) is normal subtraction modulo 59"
	# Python's modulo operator handles negitive numbers. If we didn't, we
	# could just add 59 to a before subtracting b
	return intmod((int(a) - int(b)) % intmod.base)

    def __rsub__(a, b):
        # We have to reverse the argument order for rsub
	return intmod((int(b) - int(a)) % intmod.base)

    def __neg__(self):
        return int((intmod.base - int(self)) % intmod.base)
    
    def __mul__(a, b):
        "Multiplication in PF(59)"
        return intmod((int(a) * int(b)) % intmod.base)
    __rmul__ = __mul__

    def __pow__(self, power):
        if isinstance(power, intmod):
            raise TypeError("Raising a Field element to another Field element is not defined. power must be a regular integer")
        if (power < 0):
            return intmod(pow(int(self), -power, intmod.base)).inverse()
        return intmod(pow(int(self), power, intmod.base))

    def inverse(self):
        return intmod(intmod.invtable[self])

    def __div__(self, other):
        return self * intmod(other).inverse()
    def __rdiv__(self, other):
        return self.inverse() * other

    def __repr__(self):
        n = self.__class__.__name__
        return "%s(%r)" % (n, int(self))
        
    @classmethod
    def rand(cls):
        while True:
            c=ord(os.urandom(1))
            if c<(255-255%intmod.base):
                return intmod(c%intmod.base)
    multiply = __mul__
